use std::sync::Arc;

use anyhow::Result;
use log::debug;

use cgroups_rs::Cgroup;
use nix::unistd::Pid;
use tokio::{select, sync::broadcast};

use krata::idm::{
  client::{IdmClientStreamResponseHandle, IdmInternalClient},
  internal::{
    event::Event as EventType, request::Request as RequestType,
    response::Response as ResponseType, Event, ExecStreamResponseUpdate, ExitEvent,
    MetricsResponse, PingResponse, Request, Response,
  },
};

use crate::{
  childwait::{ChildEvent, ChildWait},
  death,
  exec::GuestExecTask,
  metrics::MetricsCollector,
  supervisor::{Supervisor}
};

pub struct GuestBackground {
  idm: IdmInternalClient,
  child: Pid,
  _cgroup: Cgroup,
  wait: ChildWait,
  supervisor: Supervisor,
}

impl GuestBackground {
  pub async fn new(
    idm: IdmInternalClient,
    cgroup: Cgroup,
    child: Pid,
    supervisor: Supervisor,
  ) -> Result<GuestBackground> {
    Ok(GuestBackground {
      idm,
      child,
      _cgroup: cgroup,
      wait: ChildWait::new()?,
      supervisor,
    })
  }

  pub async fn run(&mut self) -> Result<()> {
    let mut event_subscription = self.idm.subscribe().await?;
    let mut requests_subscription = self.idm.requests().await?;
    let mut request_streams_subscription = self.idm.request_streams().await?;
    loop {
      select! {
        x = event_subscription.recv() => match x {
          Ok(_event) => {},
          Err(broadcast::error::RecvError::Closed) => {
            debug!("idm packet channel closed");
            break;
          },
          _ => { continue; }
        },
        x = requests_subscription.recv() => match x {
          Ok((id, request)) => {
            self.handle_idm_request(id, request).await?;
          },
          Err(broadcast::error::RecvError::Closed) => {
            debug!("idm packet channel closed");
            break;
          },
          _ => { continue; }
        },
        x = request_streams_subscription.recv() => match x {
          Ok(handle) => {
            self.handle_idm_stream_request(handle).await?;
          },
          Err(broadcast::error::RecvError::Closed) => {
            debug!("idm packet channel closed");
            break;
          },
          _ => { continue; }
        },
        event = self.wait.recv() => match event {
          Some(event) => self.child_event(event).await?,
          None => { break; }
        }
      };
    }
    Ok(())
  }

  async fn handle_idm_request(&mut self, id: u64, packet: Request) -> Result<()> {
    match packet.request {
      Some(RequestType::Ping(_)) => {
        self.idm
          .respond(
            id,
            Response {
              response: Some(ResponseType::Ping(PingResponse {})),
            },
          )
          .await?;
      }

      Some(RequestType::Metrics(_)) => {
        let metrics = MetricsCollector::new()?;
        let root = metrics.collect()?;
        let response = Response {
          response: Some(ResponseType::Metrics(MetricsResponse { root: Some(root) })),
        };

        self.idm.respond(id, response).await?;
      }

      _ => {}
    }
    Ok(())
  }

  async fn handle_idm_stream_request(
    &mut self,
    handle: IdmClientStreamResponseHandle<Request>,
  ) -> Result<()> {
    if let Some(RequestType::ExecStream(_)) = &handle.initial.request {
      let supervisor = self.supervisor.clone();
      tokio::task::spawn(async move {
        let exec = GuestExecTask { handle, supervisor };
        if let Err(error) = exec.run().await {
          let _ = exec
            .handle
            .respond(Response {
              response: Some(ResponseType::ExecStream(ExecStreamResponseUpdate {
                exited: true,
                error: error.to_string(),
                exit_code: -1,
                stdout: vec![],
                stderr: vec![],
              })),
            })
            .await;
        }
      });
    }
    Ok(())
  }

  async fn child_event(&mut self, event: ChildEvent) -> Result<()> {
    if event.pid == self.child {
      self.idm
        .emit(Event {
          event: Some(EventType::Exit(ExitEvent { code: event.status })),
        })
        .await?;
      death(event.status).await?;
    }
    Ok(())
  }
}
