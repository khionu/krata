// - Find all the unsafe calls that need wrapping/documenting
// - Strategy/Retry builder API
// - API for kratactl integration
// - Final documentation pass: code, docs, and architecture
// - Write up Notion page on tech debt
//   - Make our own libc wrappers
//   - Panic/error reporting
//   - AtomicId table should be on disk
//   - Mono-module is gross: break it up, library later
// - Write up future features for Supervisor
//   - Task mailbox
//   - IDM channel for inter-process backpane
//   - Use DI to avoid closure captures messing with lifetimes and Send/Sync
// - Ensure Branch Status is updated everywhere appropriate
// ------ Test with rpc-exec, then expose for Workloads, then internal tasks over time

use std::{
  collections::VecDeque,
  error::Error,
  ffi::CString,
  future::Future,
  io,
  fmt::Display,
  hash::{Hash, Hasher},
  marker::PhantomData,
  mem::MaybeUninit,
  os::fd::{AsRawFd, IntoRawFd, RawFd},
  path::{Path, PathBuf},
  pin::Pin,
  ptr::addr_of_mut,
  sync::{Arc, atomic::{AtomicU32, Ordering}},
  task::{Context, Poll, ready},
  time::Duration,
};

use anyhow::{bail, ensure, Context as _, Result};
use dashmap::{DashMap, DashSet};
use log::{error, info, warn};

use cgroups_rs::{Cgroup, CgroupPid};
use futures::{future::{BoxFuture, FutureExt}, stream::Stream};
use libc::{
  c_int, uid_t, gid_t, pid_t, waitpid, 
  TIOCSCTTY, WEXITSTATUS, WIFEXITED, WNOHANG
};
use nix::{
  ioctl_write_int_bad,
  unistd::Pid
};
use tokio::{
  io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    BufReader, BufWriter, Interest, ReadBuf, unix::AsyncFd},
  process::{ChildStdin, ChildStdout, ChildStderr},
  runtime::Handle,
  select,
  sync::{Barrier, broadcast, mpsc, Mutex, MutexGuard, Notify, OnceCell, oneshot, RwLock},
  task as atask,
  time::{Instant, sleep},
};

use crate::AsyncCondvar;

ioctl_write_int_bad!(set_controlling_terminal, TIOCSCTTY);

// Terminology
// - Branch: a child process or spawned task.
// - Child: a child process
// - Task: a unit of work on the async executor
// - Workload: a Krata unit of work

#[derive(Clone)]
pub struct AtomicId {
  inner: Arc<u32>,
  pool: mpsc::Sender<u32>,
}

impl PartialEq for AtomicId {
  fn eq(&self, other: &Self) -> bool {
    self.inner == other.inner
  }
}

impl Eq for AtomicId { }

impl Hash for AtomicId{
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.inner.hash(state);
  }
}

// We're excluding the channel for returning to the pool
impl std::fmt::Debug for AtomicId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    f.debug_struct("AtomicId")
      .field("inner", &*self.inner)
      .finish()
  }
}

impl Drop for AtomicId {
  fn drop(&mut self) {
    // If we are the last, we return the value to the pool
    if Arc::strong_count(&self.inner) <= 1 && Arc::weak_count(&self.inner) <= 1 {
      let _ = self.pool.blocking_send(self.inner.as_ref().clone());
    }
  }
}

impl Display for AtomicId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::fmt::Display::fmt(&*(self.inner), f)
  }
}

#[derive(Debug, Clone)]
pub struct AliveHandle(Arc<Mutex<bool>>, Arc<AsyncCondvar>);

#[derive(Debug)]
pub struct IsDead;

// TODO: Maybe this should give more info?
impl Display for IsDead {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "it's dead, Jim")
  }
}

impl Error for IsDead {}

impl AliveHandle {
  fn new() -> Self {
    Self(Arc::new(Mutex::new(true)), Arc::new(AsyncCondvar::new()))
  }

  pub async fn until_dead_wait_other<'a, T>(&self, guard: MutexGuard<'a, T>, condvar: &AsyncCondvar)
    -> Result<MutexGuard<'a, T>, IsDead>
  {
    let alive = self.0.lock().await;

    if !*alive { return Err(IsDead); }

    select! {
      g = condvar.wait(guard) => Ok(g),
      _ = self.1.wait(alive) => Err(IsDead),
    }
  }

  pub async fn wait(&self) {
    let alive = self.0.lock().await;

    if !*alive { return; }

    let _ = self.1.wait(alive).await;
  }
}

#[derive(Clone, Debug)]
pub struct Supervisor {
  // TODO: associated types on the Spec trait make this impossible.
  // Make the trait private and somehow store as an enum
  // specs: DashMap<AtomicId, Arc<dyn Spec>>,
  statuses: Arc<DashMap<AtomicId, StatusHandle>>,
  // If a child is fatal for the whole tree, this.
  fatal_notify: Arc<Notify>,
  // AtomicID fields
  id_return_rx: Arc<Mutex<mpsc::Receiver<u32>>>,
  id_return_tx: mpsc::Sender<u32>,
  id_cursor: Arc<AtomicU32>,

  reaper_interrupt: Arc<Mutex<()>>,
  reaper_handles: Arc<DashMap<pid_t, oneshot::Sender<c_int>>>,
}

/// Strategy passed with Command
#[derive(Debug, Copy, Clone)]
pub struct Strategy {
  /// If true, the death of the child will cascade up
  pub fatal: bool,
  /// Whether and how to retry the child
  pub retry: Option<Retry>,
  /// If set, accepts this as a successful error code and to not retry.
  pub success_code: Option<i32>,
}

/// Options used for retrying in a supervison strategy
#[derive(Debug, Copy, Clone)]
pub struct Retry {
  /// Number of attempts before giving up. `None` is infinite.
  pub attempts: Option<u8>,
  /// Time before resetting attempt counter, in ms
  pub cooldown: u32,
  /// The base time to wait between Branch retries, in ms.
  /// 
  /// With or without exp_backoff, this is capped at 5 minutes.
  pub retry_delay: u32,
  /// If some, exponential back off is used at this rate.
  /// `retry_delay * exp_backoff.pow(attempts)`
  pub exp_backoff: Option<f32>,
}

impl Strategy {
  /// The evaluation of the supervision strategy
  async fn eval_retry(
    self,
    status_code: Option<i32>,
    counter: &mut u8,
    last_start: Instant
  ) -> StrategyResult {
    let Strategy { retry, fatal, success_code } = self;
   
    // If the status code of the branch matches the success code,
    // we don't want to retry, as it's already succeeded.
    if status_code == success_code {
      return StrategyResult::Success;
    }
   
    if let Some(Retry { attempts, cooldown, retry_delay, exp_backoff }) = retry {
      // If the retry cooldown has been exceeded, reset the counter
      if last_start.elapsed() > Duration::from_millis(cooldown as u64) {
        *counter = 0;
      }
   
      // If we're at/past max retries, we stop
      // If attempts is None, we retry infinitely
      if let Some(max) = attempts {
        if max <= *counter {
          return StrategyResult::stop(fatal);
        }
      }
   
      // Else we retry
   
      // Insert a delay before retrying, half-second intervals, with an opt-in 1.5
      // exponential backoff, capped out at 5 min.
      let delay = match exp_backoff {
        Some(exp) if exp.is_normal() => 
          (unsafe {
            retry_delay * (exp.powi(*counter as i32)).to_int_unchecked::<u32>()
          }) as u64,
        _ => retry_delay as u64,
      };
   
      const FIVE_MIN_IN_MS: u64 = 5 * 60 * 1000;
      let delay = u64::min(delay, FIVE_MIN_IN_MS);
   
      sleep(Duration::from_millis(delay)).await;
   
      return StrategyResult::Restart;
    }
   
    StrategyResult::stop(fatal)
  }

}

pub type StatusHandle = Arc<RwLock<Status>>;

#[derive(Debug, Clone)]
pub enum Status {
  Started,
  Running,
  Exited(i32),
}

/// A specification for how to spawn and supervise an async task.
//#[derive(Clone)]
//pub struct TaskSpec {
//  pub builder: TaskBuilder,
//  pub strategy: Strategy,
//}

//#[derive(Clone)]
//struct TaskAlloc<T: Send + 'static> {
//  id: AtomicId,
//  sup: Supervisor,
//  strategy: Strategy,
//  alive: AliveHandle,
//  restart: Arc<Notify>,
//  builder: TaskBuilder<T>,
//  ctx: TaskCtx,
//}

//impl<T: Send + 'static> TaskAlloc<T> {
//  fn new(
//    id: AtomicId,
//    sup: Supervisor,
//    alive: AliveHandle,
//    restart: Arc<Notify>,
//    builder: TaskBuilder<T>,
//  ) -> Self {
//    Self {
//      id,
//      sup,
//      strategy,
//      alive,
//      restart,
//      builder,
//    }
//  }
// 
//  async fn run(&mut self) -> Result<i32> {
//    self.builder.run(
//  }
//}

/// A function that returns a Future to be spawned and supervised.
///
/// The Future's return value is used only for the Retry and sharing over RPC.
///
/// WARNING: Do not spawn the task from inside this function. The
/// point of this function is to give the Supervisor what is to be 
/// supervised.
//pub struct TaskBuilder<T: Send + 'static> {
//  state: T,
//  func: impl Fn(&mut T, &TaskCtx) -> SpawnFuture,
//}

//impl<T: Send + 'static> TaskBuilder {
//  pub fn new(state: T, func: BranchBuilderFn) -> Self {
//    Self { state, func }
//  }
//
//  pub async fn run(&mut self, ctx: &TaskCtx) -> Result<i32> {
//    self.func(&mut self.state, ctx).await
//  }
//}

/// Context passed at the spawn of each supervised task, giving 
/// the task access to various pieces of general-purpose APIs.
/// Eventually, this could expose mailboxes and other Actor-
/// inspired features.
//#[derive(Debug, Clone)]
//pub struct TaskCtx {
//  handle: TaskHandle,
//}

//impl TaskCtx {
//  pub fn supervisor(&self) -> Supervisor {
//    self.handle.sup.clone()
//  }
//}

//#[derive(Debug, Clone)]
//pub struct TaskHandle {
//  id: AtomicId,
//  sup: Supervisor,
//  alive: AliveHandle,
//  restart: Arc<Notify>,
//}

// TODO: make it possible to spawn child Tasks that are also 
// supervised. This will become the backbone of Supervision
// Trees.
//impl TaskCtx {
//  fn new(handle: TaskHandle) -> Self {
//    Self {
//      handle,
//    }
//  }
//}

/// Command used to spawn a child process
#[derive(Debug, Clone)]
pub struct ChildSpec {
  /// The executable, with or without path, path relative
  /// or absolute, to run.
  pub cmd: PathBuf,
  /// The args to pass
  pub args: Vec<CString>,
  /// Env vars to be set
  pub env: Vec<CString>,
  /// Working directory to set just before spawning
  pub working_dir: String,
  /// Cgroup we'll use for the child
  pub cgroup: Option<Cgroup>,
  /// Whether to create the child in a new session
  /// This is mainly for image entrypoint
  pub with_new_session: bool,
  /// Strategy to use on child's death
  pub strategy: Strategy,
  /// Whether to use tty
  pub tty: bool,
}

#[derive(Clone)]
struct ChildBuilder {
  id: AtomicId,
  spec: ChildSpec,
  alive: AliveHandle,
  stdin_swapbox:  FdSwapboxHandle,
  stdout_swapbox: FdSwapboxHandle,
  stderr_swapbox: FdSwapboxHandle,
}

pub struct ChildHandle {
  id: AtomicId,
  pub stdin:  Option<Stdin>,
  pub stdout: Option<Stdout>,
  pub stderr: Option<Stderr>,
  supervisor: Supervisor,
  alive: AliveHandle,
}

//impl TaskSpec {
//  fn alloc(
//    &self,
//    sup: Supervisor,
//    id: AtomicId,
//    alive: AliveHandle,
//    restart: Arc<Notify>,
//  ) -> (BranchBuilderFn, NewHandle) {
//    let handle = TaskHandle { id, sup, alive, restart };
//    let context = TaskCtx { handle: handle.clone() };
//  
//    let spec = self.clone();
//    let builder = || async move {
//      let state_ref = &mut spec.state;
//      spec.builder.lock()
//          .await
//          .run(state_ref, &context)
//          .await
//    };
//  
//    (builder, NewHandle::AsyncTask(handle))
//  }
//  
//  async fn run(&self, builder: BranchBuilderFn) -> Result<i32> {
//    builder().await
//  }
//}

impl ChildSpec {
  fn alloc(
    &self,
    sup: Supervisor,
    id: AtomicId,
    alive: AliveHandle,
    restart: Arc<Notify>,
  ) -> (ChildBuilder, ChildHandle) {
    let restart_barrier = Arc::new(Barrier::new(3));
    let stdin = Stdin {
      inner: Stdio::new(alive.clone(), restart_barrier.clone(), true)
    };
    let stdout = Stdout {
      inner: Stdio::new(alive.clone(), restart_barrier.clone(), false)
    };
    let stderr = Stderr {
      inner: Stdio::new(alive.clone(), restart_barrier.clone(), false)
    };

    let builder = ChildBuilder {
      id: id.clone(),
      spec: self.clone(),
      alive: alive.clone(),
      stdin_swapbox: stdin.inner.fd_swapbox.clone(),
      stdout_swapbox: stdout.inner.fd_swapbox.clone(),
      stderr_swapbox: stderr.inner.fd_swapbox.clone(),
    };

    let handle = ChildHandle {
      id,
      stdin: Some(stdin),
      stdout: Some(stdout),
      stderr: Some(stderr),
      supervisor: sup,
      alive
    };

    (builder, handle)
  }

  async fn run(&self, builder: &'_ mut ChildBuilder, sup: &Supervisor) -> Result<i32> {
    // Lock the reaper so we don't race against the spawn internals
    let g = sup.reaper_interrupt.lock().await;
    let pidfd = builder.spawn().await?;
    let (tx, rx) = oneshot::channel();
    sup.reaper_handles.insert(pidfd, tx);

    // SAFETY: the reaper always consumes the sender if in the map
    Ok(rx.await.unwrap())
  }
}

impl ChildHandle {
  pub async fn wait(&mut self) -> i32 {
    self.alive.wait().await;

    let Some(status_handle) = self.supervisor.statuses.get(&self.id)
      else {
        error!("status handle missing for child {}", self.id);
        return 0;
      };

    let Status::Exited(code) = *(status_handle.read().await)
      else {
        error!("status handle not updated to reflect child death. This is a race condition with the AliveHandle, which should always be set after Status::Exited");
        return 1;
      };

    code
  }
}

enum StrategyResult {
  Started,
  Success,
  Restart,
  Stop,
  Fatal,
}

impl StrategyResult {
  fn stop(fatal: bool) -> Self {
    if !fatal {
      Self::Stop
    } else {
      Self::Fatal
    }
  }
}

impl ChildBuilder {
  async fn spawn(&mut self) -> Result<RawFd> {
    use std::os::unix::ffi::OsStrExt;

    let ChildSpec {
      cmd,
      args,
      env,
      working_dir,
      cgroup,
      with_new_session,
      tty,
      ..
    } = &self.spec;
   
    let stdio = if *tty { 
      StdioSet::new_pty().context("failed to spawn pty")?
    } else {
      StdioSet::new_pipes().context("failed to alloc pipes")?
    };
   
    let StdioSet {
      parent, child
    } = stdio;

    // `file_actions` and `spawnattrs` are Copy, so we need a scope to ensure they're "dropped"
    // before our async Mutex locks
    let pidfd = { 
      let file_actions: libc::posix_spawn_file_actions_t = unsafe {
        let mut file_actions = MaybeUninit::uninit();
        libc::posix_spawn_file_actions_init(file_actions.as_mut_ptr());
        libc::posix_spawn_file_actions_adddup2(
          file_actions.as_mut_ptr(),
          child.stdin, libc::STDIN_FILENO
        );
        libc::posix_spawn_file_actions_adddup2(
          file_actions.as_mut_ptr(),
          child.stdout, libc::STDOUT_FILENO
        );
        libc::posix_spawn_file_actions_adddup2(
          file_actions.as_mut_ptr(),
          child.stderr, libc::STDERR_FILENO
        );
   
        file_actions.assume_init()
      };
     
      let spawnattr: libc::posix_spawnattr_t = unsafe {
        let mut spawnattr = MaybeUninit::uninit();
        libc::posix_spawnattr_init(spawnattr.as_mut_ptr());
        // SAFETY: Both flags use 8 bits or less
        #[allow(overflowing_literals)]
        let mut flags = libc::POSIX_SPAWN_SETPGROUP as i16;
        if *with_new_session {
          flags |= libc::POSIX_SPAWN_SETSID as i16;
        }
   
        libc::posix_spawnattr_setflags(spawnattr.as_mut_ptr(), flags);
        spawnattr.assume_init()
      };
    
      let old_working_dir = std::env::current_dir().context("failed to retriev CWD")?;
      std::env::set_current_dir(working_dir).context("failed to change CWD")?;
      
      let mut pid: pid_t = 0;
   
      let spawn = match &cmd.parent() {
        Some(p) if p == &Path::new("") => libc::posix_spawnp,
        None => libc::posix_spawnp,
        _ => libc::posix_spawn,
      };
   
      // SAFETY: We're using the raw underlying value, then rewrapping it for Drop
      let res = unsafe {
        let cmd = CString::new(cmd.as_os_str().as_encoded_bytes())?;
        let args = args.into_iter().map(|a| {
          let a = a.clone();
          a.into_raw()
        }).collect::<Vec<*mut i8>>();
        let env = env.into_iter().map(|e| {
          let e = e.clone();
          e.into_raw()
        }).collect::<Vec<*mut i8>>();
   
        // TODO: Safety comment
        let res = spawn(
          addr_of_mut!(pid),
          cmd.as_ptr(),
          &file_actions,
          &spawnattr,
          args.as_slice().as_ptr(),
          env.as_slice().as_ptr(),
        );
   
        let _ = args.into_iter().map(|a| CString::from_raw(a));
        let _ = env.into_iter().map(|e| CString::from_raw(e));
        
        res
      };
   
      std::env::set_current_dir(old_working_dir).context("failed to restore previous CWD")?;
   
      if res != 0 {
        error!("Failed to spawn process: return value of {res}");
        return Err(io::Error::last_os_error().into());
      }
     
      if let Some(cg) = cgroup {
        cg.add_task(CgroupPid::from(pid as u64)).context("failed to add child to cgroup")?;
      }
  
      // TODO: Bring this back some time?
      // // SAFETY: We have ensured that the spawn was successful
      // unsafe {
      //   libc::syscall(libc::SYS_pidfd_open, pid, libc::PIDFD_NONBLOCK)
      // }
      pid
    };

    self.stdin_swapbox.0.lock().await.replace(parent.stdin);
    self.stdout_swapbox.0.lock().await.replace(parent.stdout);
    self.stderr_swapbox.0.lock().await.replace(parent.stderr);

    self.stdin_swapbox.1.signal();
    self.stdout_swapbox.1.signal();
    self.stderr_swapbox.1.signal();

    // SAFETY: pidfd's are always positive, ergo signing bit is always 0
    // NOTE: at this time, this is not actually a pidfd, it is a pid, but unsure how we'll proceed
    // for now, so leaving this as is. See above TODO
    #[allow(overflowing_literals)]
    Ok(pidfd as c_int)
  }

  async fn wait_loop(pidfd: RawFd) -> Result<i32> {
    loop {
      let mut status: MaybeUninit<libc::siginfo_t> = MaybeUninit::uninit();
      let code = unsafe { 
        libc::waitid(libc::P_PIDFD,
                     // TODO: do this right
                     // SAFETY: Idfc atm
                     pidfd.try_into().unwrap(),
                     status.as_mut_ptr(),
                     libc::WNOHANG | libc::WEXITED
        )
      };
      if code == -1 {
        bail!(io::Error::last_os_error());
      }
      let status = unsafe { status.assume_init() };

      match status.si_code {
        libc::CLD_EXITED | libc::CLD_KILLED
        | libc::CLD_DUMPED | libc::CLD_STOPPED =>
          // SAFETY: We checked the code to make sure the status
          // is what we're looking for
          unsafe{ return Ok(status.si_status()) },
        _ => atask::yield_now().await,
      }
    }
  }
}

impl Supervisor {
  pub fn new() -> Self {
    let (id_return_tx, id_return_rx) = mpsc::channel(64);
    let id_return_rx = Arc::new(Mutex::new(id_return_rx));

    Self {
      statuses: Arc::new(DashMap::new()),
      fatal_notify: Arc::new(Notify::new()),
      id_return_rx,
      id_return_tx,
      id_cursor: Arc::new(AtomicU32::new(0)),
      reaper_interrupt: Arc::new(Mutex::new(())),
      reaper_handles: Arc::new(DashMap::new()),
    }
  }

  /// Block on the Supervisor's units completing
  pub async fn run_to_end(&self) {
    // TODO: Supervisor should reap all child processes and tasks
    // on fatality
    let n = self.fatal_notify.clone();
    n.notified().await;
  }

  /// Spawn the process reaper for the init, to clean up orphaned processes
  pub async fn spawn_reaper(&self) {
    let sup = self.clone();
    atask::spawn(async move { loop {
      if let Err(e) = sup.reaper_task().await {
        error!("Supervisor reaper encountered a fatal error: {e}");
      }
    }});
//  self.spawn_async(TaskSpec {
//    builder: |ctx| Self::reaper_task(ctx),
//    strategy: Strategy {
//      fatal: false,
//      retry: Some(Retry {
//        attempts: None, // Infinite retries, the reaper must never die
//        cooldown: 0,
//        retry_delay: 0,
//        exp_backoff: None,
//      }),
//      success_code: None,
//    }
//  }).a c_int
  }

  async fn reaper_task(&self) -> Result<i32> {
    use std::io::ErrorKind;

    loop {
      let g = self.reaper_interrupt.lock().await;
      let mut status: c_int = 0;
      let pid = unsafe { waitpid(-1, addr_of_mut!(status), WNOHANG) };
      drop(g);

      if pid > 0 {
        if let Some((_, tx)) = self.reaper_handles.remove(&pid) {
          info!("Reaped process {pid}, sending exit code");
          tx.send(status);
        }
        // TODO: Report to dom0 via TaskCtx
        // Blocked on getting IDM client wired
        warn!("Reaped zombie process {pid:?}");
      }

      if pid == -1 {
        let err = io::Error::last_os_error();

        if let Some(10) = err.raw_os_error() {
          atask::yield_now().await;
          continue;
        } else {
          return Err(err.into());
        }
      }

      atask::yield_now().await;
    }
  }

//pub async fn spawn_async(&self, spec: TaskSpec) -> TaskHandle {
//  let NewHandle::AsyncTask(handle) = self.spawn_internal(spec).await else {
//    unreachable!("Always will resolve to AsyncTask when passed TaskSpec");
//  };
//  handle
//}

  pub async fn spawn_process(&self, spec: ChildSpec) -> ChildHandle {
    use StrategyResult::*;

    let id = self.alloc_id().await;
    let status = Arc::new(RwLock::new(Status::Started));
    let alive_handle = AliveHandle::new();
    let restart_sig = Arc::new(Notify::new());
    let strat = spec.strategy;

    if let Some(Retry { exp_backoff: Some(e), .. }) = strat.retry {
      if !e.is_normal() {
        warn!("exp_backoff is abnormal, performing linear retry delays");
      }
    }

    // TODO: See field comment
    // self.specs.insert(id.clone(), Arc::new(spec.clone()));
    self.statuses.insert(id.clone(), status.clone());

    let delay_till_running = Duration::from_millis(
      strat.retry
        .clone()
        .map(|r| r.cooldown)
        .unwrap_or(500)
        .into()
    );

    let status_copy = status.clone();
    atask::spawn(async move {
      sleep(delay_till_running).await;
      *(status_copy.write().await) = Status::Running;
    });

    let (mut builder, handle) = spec.alloc(
      self.clone(),
      id,
      alive_handle,
      restart_sig.clone(),
    );

    let sup = self.clone();
    atask::spawn(async move {
      //let builder = builder;
      let restart_sig = restart_sig;
      let sup = &sup;
      let mut retry_counter = 0u8;
      loop {
        let start_time = Instant::now();
        let result = match spec.run(&mut builder, sup).await {
          Ok(r) => r,
          Err(err) => {
            error!("Supervised unit failed to start: {err}");
            return;
          }
        };
      
       // if let Err(err) = &result {
       //   error!("Supervised unit stopped with error: {err}");
       // }

       // let result = result.ok();
   
        let step = strat.eval_retry(Some(result), &mut retry_counter, start_time).await;
        
        if let Restart = step {
          continue;
        }
   
        if let Success | Stop | Fatal = step {
          *(status.write().await) = Status::Exited(result);
        }
   
        if let Fatal = step {
          sup.fatal_notify.notify_waiters();
        }
   
        restart_sig.notify_waiters();
      }
    });

    handle
  }

  async fn alloc_id(&self) -> AtomicId {
    use mpsc::error::TryRecvError;

    let inner = match self.id_return_rx.lock().await.try_recv() {
      Ok(i) => i,
      Err(TryRecvError::Empty) => self.id_cursor.fetch_add(1, Ordering::AcqRel),
      _ => unreachable!("Always one copy of sender in static"),
    };

    AtomicId {
      inner: Arc::new(inner),
      pool: self.id_return_tx.clone(),
    }
  }
}

struct StdioReadLock {
  fd: AsyncFd<i32>,
}

impl StdioReadLock {
  fn raw_read(&self, buf: &mut ReadBuf<'_>) -> io::Result<()> {
    let count = buf.remaining();

    let res = unsafe {
      libc::read(*self.fd.get_ref(), buf.initialize_unfilled().as_mut_ptr().cast(), count)
    };

    if res == -1 {
      return Err(io::Error::last_os_error());
    }

    // SAFETY: res will be between -1 and ~8 million, and we've already ruled out -1
    buf.advance(res.try_into().unwrap());

    Ok(())
  }
}

impl AsyncRead for StdioReadLock {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>
  ) -> Poll<io::Result<()>> {
    loop {
      let mut guard = ready!(self.fd.poll_read_ready(cx))?;

      match guard.try_io(|_| self.raw_read(buf)) {
        Ok(r) => return Poll::Ready(r),
        Err(_) => continue,
      }
    }
  }
}

struct StdioWriteLock {
  fd: AsyncFd<i32>,
}

impl StdioWriteLock {
  fn raw_write(&self, buf: &[u8]) -> io::Result<usize> {
    let res = unsafe {
      libc::write(*self.fd.get_ref(), buf.as_ptr().cast(), buf.len())
    };

    if res == -1 {
      return Err(io::Error::last_os_error());
    }

    // SAFETY: res will be between -1 and ~8 million, and we've already ruled out -1
    Ok(res.try_into().unwrap())
  }
}

impl AsyncWrite for StdioWriteLock {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8]
  ) -> Poll<io::Result<usize>> {
    loop {
      let mut guard = ready!(self.fd.poll_write_ready(cx))?;

      match guard.try_io(|_| self.raw_write(buf)) {
        Ok(r) => return Poll::Ready(r),
        Err(_) => continue,
      }
    }
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>
  ) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>
  ) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

type StdioMutex = Mutex<VecDeque<Vec<u8>>>;
type StdioFdSwapbox = Arc<Mutex<Option<RawFd>>>;

/// Wraps the parent side of an stdio channel.
#[derive(Debug, Clone)]
pub struct Stdio {
  queue: (Arc<StdioMutex>, Arc<AsyncCondvar>),
  fd_swapbox: FdSwapboxHandle,
  alive: AliveHandle,
  restart_barrier: Arc<Barrier>,
}

#[derive(Debug, Clone)]
struct FdSwapboxHandle(StdioFdSwapbox, Arc<AsyncCondvar>);

impl FdSwapboxHandle {
  fn new() -> Self {
    Self(Arc::new(Mutex::new(None)), Arc::new(AsyncCondvar::new()))
  }
}

#[derive(Debug, Clone)]
pub struct Stdin {
  inner: Stdio,
}

#[derive(Debug, Clone)]
pub struct Stdout {
  inner: Stdio,
}

#[derive(Debug, Clone)]
pub struct Stderr {
  inner: Stdio,
}

impl Stdio {
  // If None, the child is true-dead, as opposed to restarting
  async fn fetch_new_fd(&self) -> Result<RawFd> {
    let mut fd_g = self.fd_swapbox.0.lock().await;
    // The swapbox should be None if there's not been one swapped in
    match (*fd_g).take() {
      Some(fd) => Ok(fd),
      None => {
        // If we're true-dead, we don't want our caller to continue
        match self.alive.until_dead_wait_other(fd_g, &self.fd_swapbox.1).await {
          Ok(mut new) => Ok((*new).take().ok_or(IsDead)?),
          Err(_) => bail!(IsDead),
        }
      },
    }
  }

  fn spawn_read(&self) {
    use std::io::ErrorKind;
    use tokio::io::{Interest, unix::AsyncFd};

    let this = (*self).clone();

    atask::spawn(async move {
      'child: loop {
        let fd = this.fetch_new_fd().await?;
        // Safety: if this fails, we have a bug in our pty/pipe allocations
        let async_fd = AsyncFd::with_interest(fd, Interest::READABLE)
          .expect("async io failure");
        let read_lock = StdioReadLock { fd: async_fd };
        let mut reader = BufReader::new(read_lock);
    
        'write: loop {
          let mut g = this.queue.0.lock().await;
          // TODO: use zeroable array, move on <0, zero every time
          let mut buf = Vec::with_capacity(8192);
    
          match reader.read_buf(&mut buf).await {
            Ok(n) if n > 0 => (*g).push_back(buf),
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {
              this.restart_barrier.wait().await;
            }
            Err(e) => error!("Error reading from stdio: {e:?}"),
            _ => {},
          }
        }
      }

      Ok::<(), anyhow::Error>(())
    });
  }

  fn spawn_write(&self) {
    use std::io::ErrorKind;

    let this = (*self).clone();

    atask::spawn(async move {
      'child: loop {
        let fd = this.fetch_new_fd().await?;
        // Safety: if this fails, we have a bug in our pty/pipe allocations
        let async_fd = AsyncFd::with_interest(fd, Interest::WRITABLE)
          .expect("async io failure");
        let write_lock = StdioWriteLock { fd: async_fd };
        let mut writer = BufWriter::new(write_lock);
   
        'write: loop {
          let mut g = this.queue.0.lock().await;
          let mut u: VecDeque<u8> = match (*g).pop_front() {
            Some(u) => u.into(),
            None => {
              let _ = this.alive.until_dead_wait_other(g, &this.queue.1).await?;
              continue 'write;
            },
          };
   
          match writer.write_all_buf(&mut u).await {
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {
              (*g).drain(0..);
              // TODO: signal
              let _ = this.restart_barrier.wait().await;
              continue 'child;
            }
            Ok(_) => {},
            Err(err) => error!("error during stdin: {err:?}"),
          }
        }
      }

      Ok::<(), anyhow::Error>(())
    });
  }

  async fn send_val(&self, val: Vec<u8>) -> Result<()> {
    let mut g = self.queue.0.lock().await;
    g = self.alive.until_dead_wait_other(g, &self.queue.1).await?;

    (*g).push_back(val);

    self.queue.1.signal();

    Ok(())
  }

  async fn wait_for_val(&self) -> Result<Vec<u8>> {
    let mut g = self.queue.0.lock().await;

    loop {
      match (*g).pop_front() {
        Some(val) => return Ok(val),
        None => {
          g = self.alive.until_dead_wait_other(g, &self.queue.1).await?;
        }
      }
    }
  }

  fn new(alive: AliveHandle, restart_barrier: Arc<Barrier>, write: bool) -> Self {
    let this = Self {
      queue: (
        Arc::new(Mutex::new(VecDeque::with_capacity(8))),
        Arc::new(AsyncCondvar::new())
      ),
      fd_swapbox: FdSwapboxHandle::new(),
      alive,
      restart_barrier,
    };

    if write {
      this.spawn_write();
    } else {
      this.spawn_read();
    }

    this
  }
}

impl Stdin {
  /// Async send a payload to the child.
  ///
  /// This errors only if the child is dead and won't be restarted.
  pub async fn send(&self, payload: Vec<u8>) -> Result<()> {
    self.inner.send_val(payload).await
  }
}

impl Stdout {
  /// Async block until we get a value.
  ///
  /// This errors only if the child is dead and won't be restarted.
  pub async fn recv(&self) -> Result<Vec<u8>> {
    self.inner.wait_for_val().await
  }
}

impl Stderr {
  /// Async block until we get a value.
  ///
  /// This errors only if the child is dead and won't be restarted.
  pub async fn recv(&self) -> Result<Vec<u8>> {
    self.inner.wait_for_val().await
  }
}

struct StdioSet {
  parent: StdioSubset,
  child: StdioSubset,
}

struct StdioSubset {
  stdin:  RawFd,
  stdout: RawFd,
  stderr: RawFd,
}

impl StdioSet {
  fn new_pty() -> Result<Self> {
    use nix::{fcntl::{self, FcntlArg, OFlag}, pty};

    // Open the Pseudoterminal with +rw capabilities and without
    // setting it as our controlling terminal
    let pty = pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY)?;
    // Grant access to the side we pass to the child
    // This is referred to as the "slave"
    pty::grantpt(&pty)?;
    // Unlock the "slave" device
    pty::unlockpt(&pty)?;

    // Retrieve the "slave" device
    let pts = {
      let name = pty::ptsname_r(&pty)?;
      std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name)?
        .into_raw_fd()
    };

    // Get the RawFd out of the OwnedFd because OwnedFd
    // sets CLOEXEC on clone
    let pty = pty.as_raw_fd();

    // Make the "master" async-ready by setting NONBLOCK
    let mut opts = OFlag::from_bits(fcntl::fcntl(pty, FcntlArg::F_GETFL)?)
      .expect("got bad O_FLAG bits from kernel");
    opts |= OFlag::O_NONBLOCK;
    fcntl::fcntl(pty, FcntlArg::F_SETFL(opts))?;

    Ok(Self {
      child: StdioSubset {
        stdin:   pts.clone(),
        stdout:  pts.clone(),
        stderr:  pts,
      },
      parent: StdioSubset {
        stdin:  pty.clone(),
        stdout: pty.clone(),
        stderr: pty,
      },
    })
  }

  fn new_pipes() -> Result<Self> {
    let (stdin_child,  stdin_parent)  = make_pipe()?;
    let (stdout_parent, stdout_child) = make_pipe()?;
    let (stderr_parent, stderr_child) = make_pipe()?;

    Ok(Self {
      parent: StdioSubset {
        stdin:  stdin_parent,
        stdout: stdout_parent,
        stderr: stderr_parent,
      },
      child: StdioSubset {
        stdin:  stdin_child,
        stdout: stdout_child,
        stderr: stderr_child,
      },
    })
  }
}

fn make_pipe() -> Result<(RawFd, RawFd)> {
  // Init two null file descriptors
  let mut raw_fds: [RawFd; 2] = [0, 0];

  // Allocate the pipe and get each end of
  let res = unsafe { libc::pipe(raw_fds.as_mut_ptr().cast()) };
  if res != 0 { return Err(io::Error::last_os_error().into()); }

  // We split the pipe into its ends so we can be explicit
  // which end is which.
  let [parent, child] = raw_fds;

  // In theory, we could do this without preserving, since
  // we created the pipe above without flags, so prev_flags
  // is guaranteed to be 0. That would save us a single
  // syscall, but this is more correct and would save someone
  // the trouble of fixing it later.
  let prev_flags = unsafe { libc::fcntl(parent, libc::F_GETFL) };
  if prev_flags == -1 { return Err(io::Error::last_os_error().into()); }

  // OR NONBLOCK into the flags
  let new_flags = prev_flags | libc::O_NONBLOCK;

  // And set the flags onto the parent
  let res = unsafe { libc::fcntl(parent, libc::F_SETFL, new_flags) };
  if res == -1 { return Err(io::Error::last_os_error().into()); }

  Ok((parent, child))
}

