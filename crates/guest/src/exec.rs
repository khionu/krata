use std::{
  collections::HashMap,
  ffi::CString,
  io::{Read, Write},
  process::{Child, Command, Stdio},
  sync::Arc,
  time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::debug;

use futures::{future::{BoxFuture, FutureExt}, join};
use pty_process::{blocking::Pty, Size};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  runtime::Handle,
  sync::Mutex,
  task,
  time::sleep,
};

use krata::idm::{
  client::IdmClientStreamResponseHandle,
  internal::{
    exec_stream_request_update::Update, request::Request as RequestType,
    ExecStreamResponseUpdate,
  },
  internal::{response::Response as ResponseType, Request, Response},
};

use crate::supervisor::{ChildSpec, Retry, Strategy, Supervisor};

pub struct GuestExecTask {
  pub handle: IdmClientStreamResponseHandle<Request>,
  pub supervisor: Supervisor,
}

impl GuestExecTask {
  pub async fn run(&self) -> Result<()> {
    let receiver = self.handle.take().await?;

    let Some(ref request) = self.handle.initial.request else {
      return Err(anyhow!("request was empty"));
    };

    let RequestType::ExecStream(update) = request else {
      return Err(anyhow!("request was not an exec update"));
    };

    let Some(Update::Start(ref start)) = update.update else {
      return Err(anyhow!("first request did not contain a start update"));
    };

    // The command, exe + args
    let mut cmd = start.command.clone();
    if cmd.is_empty() {
      return Err(anyhow!("command line was empty"));
    }

    // Pop the exe from the args
    let exe = cmd.remove(0);

    // With the exe popped, we can convert the rest to CStrings, the exe we want to save as a Path.
    let args = cmd.into_iter()
      .map(CString::new)
      .collect::<Result<Vec<CString>, _>>()?;

    let mut env = HashMap::new();
    for entry in &start.environment {
      env.insert(entry.key.clone(), entry.value.clone());
    }

    if !env.contains_key("PATH") {
      env.insert(
        "PATH".to_string(),
        "/bin:/usr/bin:/usr/local/bin".to_string(),
      );
    }
    let env = env.into_iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<Result<Vec<CString>, _>>()?;

    let working_dir = if start.working_directory.is_empty() {
      "/".to_string()
    } else {
      start.working_directory.clone()
    };

    // TODO: impl From<Update::Start> for ChildSpec
    let child_spec = ChildSpec {
      cmd: exe.into(),
      args,
      env,
      working_dir,
      cgroup: None,
      with_new_session: true,
      tty: start.tty,
      strategy: Strategy {
        fatal: false,
        retry: None,
        success_code: Some(0),
      },
    };

    let mut child = self.supervisor.spawn_process(child_spec).await;

    // let mut child = ChildDropGuard {
    //   inner: Command::new(exe)
    //     .args(cmd)
    //     .envs(env)
    //     .current_dir(dir)
    //     .stdin(Stdio::piped())
    //     .stdout(Stdio::piped())
    //     .stderr(Stdio::piped())
    //     .spawn()
    //     .map_err(|error| anyhow!("failed to spawn: {}", error))?,
    //   kill: true,
    // };
    let stdin = child
      .stdin
      .take()
      .ok_or_else(|| anyhow!("stdin was missing"))?;
    let stdout = child
      .stdout
      .take()
      .ok_or_else(|| anyhow!("stdout was missing"))?;
    let stderr = child
      .stderr
      .take()
      .ok_or_else(|| anyhow!("stderr was missing"))?;

    let stdout_handle = self.handle.clone();
    let stdout_builder = move || {
      let stdout = stdout.clone();
      let stdout_handle = stdout_handle.clone();
      async move {
        loop {
          let buf = stdout.recv().await?;
          let response = Response {
            response: Some(ResponseType::ExecStream(ExecStreamResponseUpdate {
              exited: false,
              exit_code: 0,
              error: String::new(),
              stdout: buf,
              stderr: vec![],
            })),
          };
          let _ = stdout_handle.respond(response).await;
        }
      }
    };

    let stderr_handle = self.handle.clone();
    let stderr_builder = move || { 
      let stderr = stderr.clone();
      let stderr_handle = stderr_handle.clone();
      async move {
        loop {
          let buf = (&stderr).recv().await?;
          let response = Response {
            response: Some(ResponseType::ExecStream(ExecStreamResponseUpdate {
              exited: false,
              exit_code: 0,
              error: String::new(),
              stdout: vec![],
              stderr: buf,
            })),
          };
          let _ = stderr_handle.respond(response).await;
        }
      }
    };

    let stdin_builder = move || {
      let stdin = stdin.clone();
      let receiver = Mutex::new(receiver);

      async move {
        let mut receiver = receiver.lock().await;
        loop {
          let Some(request) = receiver.recv().await else {
            bail!("Receiver channel has died");
          };
   
          let Some(RequestType::ExecStream(update)) = request.request else {
            continue;
          };
   
          let Some(Update::Stdin(update)) = update.update else {
            continue;
          };
   
          if !update.data.is_empty() {
            stdin.send(update.data).await?;
          }
   
          if update.closed {
            bail!("Exec stream closed");
          }
        }
      }
    };

    let stdin_handle:  task::JoinHandle<Result<(), anyhow::Error>>
      = task::spawn(stdin_builder());
    let stdout_handle: task::JoinHandle<Result<(), anyhow::Error>>
      = task::spawn(stdout_builder());
    let stderr_handle: task::JoinHandle<Result<(), anyhow::Error>>
      = task::spawn(stderr_builder());

    // let stdin_handle = self.supervisor.spawn_async(TaskSpec {
    //   builder: Arc::new(stdin_builder),
    //   strategy: stdio_strategy.clone(),
    // });

    // let stdout_handle = self.supervisor.spawn_async(TaskSpec {
    //   builder: Arc::new(stdout_builder),
    //   strategy: stdio_strategy.clone(),
    // });

    // let stderr_handle = self.supervisor.spawn_async(TaskSpec {
    //   builder: Arc::new(stderr_builder),
    //   strategy: stdio_strategy.clone(),
    // });

    let exit_code = child.wait().await.into();

    let response = Response {
      response: Some(ResponseType::ExecStream(ExecStreamResponseUpdate {
        exited: true,
        exit_code,
        error: String::from(""), // TODO: get this out of the Supervisor
        stdout: vec![],
        stderr: vec![],
      })),
    };
    self.handle.respond(response).await?;

    join!(stdin_handle, stdout_handle, stderr_handle);
    
    Ok(())
  }
}

