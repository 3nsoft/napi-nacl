// Copyright(c) 2025 - 2026 3NSoft Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![deny(clippy::all)]

use napi::{
  bindgen_prelude::*,
  threadsafe_function::{ThreadsafeFunctionCallMode, ThreadsafeFunction}
};
use napi_derive::napi;
use tokio::runtime::{ Runtime, Builder };
use dashmap::DashMap;
use std::sync::Arc;
use nacl;

#[napi]
pub enum EncrResult {
  Ok(Buffer),
	CipherVerificationErr,
	SignatureVerificationErr,
	ConfigurationErr(String)
}

fn into_napi_ok(nacl_result: core::result::Result<Vec<u8>, nacl::Error>) -> Result<EncrResult> {
  match nacl_result {
    Ok(buf) => Ok(EncrResult::Ok(buf.into())),
    Err(err) => match err.condition {
      nacl::ErrorCondition::CipherVerification => Ok(EncrResult::CipherVerificationErr),
      nacl::ErrorCondition::SignatureVerification => Ok(EncrResult::SignatureVerificationErr),
      nacl::ErrorCondition::Configuration => Ok(EncrResult::ConfigurationErr(err.message)),
    }
  }
}

macro_rules! compute_in {
  ($self:ident, $code:expr) => {
    {
      let result = $self.rt.spawn(async move {
        $code
      }).await.unwrap();
      match result {
        Ok(r) => Ok(r.into()),
        Err(err) => Err(Error::from_reason(err.message))
      }
    }
  }
}

macro_rules! compute_under_label_in {
  ($self:ident, $work_label:ident, $code:expr) => {
    {
      $self.increment_label_count($work_label);
      let result = $self.rt.spawn(async move {
        $code
      }).await.unwrap();
      $self.decrement_label_count($work_label);
      into_napi_ok(result)
    }
  }
}


#[napi(js_name = "AsyncSBoxCryptor")]
pub struct JsAsyncSBoxCryptor {
  labels: DashMap<u32, u32>,
  max_num_of_threads: u32,
  rt: Arc<Runtime>
}

#[napi]
impl JsAsyncSBoxCryptor {

  #[napi]
  pub fn can_start_under_work_label(&self, work_label: u32) -> u32 {
    let num_of_work_queues = self.labels.len() as u32;
    let idle = if self.max_num_of_threads <= num_of_work_queues { 0 } else {
      self.max_num_of_threads - num_of_work_queues
    };
    if idle == 0 {
      // there are more work queues in progress then there are threads,
      // but if given work queue isn't in progress, we allow one task to be added
      return if self.labels.contains_key(&work_label) { 0 } else { 1 }
    }
    match self.labels.get(&work_label) {
      Some(under_label_already) => {
        if idle <= *under_label_already  { 0 } else {
          idle - *under_label_already
        } 
      },
      None => idle
    }
  }

  fn increment_label_count(&self, work_label: u32) {
    match self.labels.get_mut(&work_label) {
      Some(mut label_count) => {
        *label_count += 1;
      },
      None => {
        self.labels.insert(work_label, 1);
      }
    }
  }

  fn decrement_label_count(&self, work_label: u32) {
    match self.labels.get_mut(&work_label) {
      Some(mut label_count) => {
        *label_count -= 1;
      },
      None => {
        return;
      }
    }
    self.labels.remove_if(&work_label, |_, &label_count| { label_count <= 0 });
  }

  #[napi]
  pub async fn open(&self, c: Buffer, n: Buffer, k: Buffer, work_label: u32) -> Result<EncrResult> {
    compute_under_label_in!(self, work_label, nacl::secret_box::open(&c, &n, &k))
  }

  #[napi]
  pub async fn pack(&self, m: Buffer, n: Buffer, k: Buffer, work_label: u32) -> Result<EncrResult> {
    compute_under_label_in!(self, work_label, nacl::secret_box::pack(&m, &n, &k))
  }

  #[napi]
  pub async fn open_format_w_n(&self, c: Buffer, k: Buffer, work_label: u32) -> Result<EncrResult> {
    compute_under_label_in!(self, work_label, nacl::secret_box::format_wn::open(&c, &k))
  }

  #[napi]
  pub async fn pack_format_w_n(&self, m: Buffer, n: Buffer, k: Buffer, work_label: u32) -> Result<EncrResult> {
    compute_under_label_in!(self, work_label, nacl::secret_box::format_wn::pack(&m, &n, &k))
  }

  fn clone(&self) -> Self {
    JsAsyncSBoxCryptor {
      rt: self.rt.clone(),
      labels: self.labels.clone(),
      max_num_of_threads: self.max_num_of_threads
    }
  }

}


#[napi(js_name = "AsyncPBox")]
pub struct JsAsyncPBox {
  rt: Arc<Runtime>
}

#[napi]
impl JsAsyncPBox {

  #[napi]
  pub async fn generate_pubkey(&self, sk: Buffer) -> Result<Buffer> {
    compute_in!(self, nacl::public_box::generate_pubkey(&sk))
  }

  #[napi]
  pub async fn calc_dhshared_key(&self, pk: Buffer, sk: Buffer) -> Result<Buffer> {
    compute_in!(self, nacl::public_box::calc_dhshared_key(&pk, &sk))
  }

}


#[napi(js_name = "Keypair")]
pub struct JsKeypair {
  #[napi]
  pub skey: Vec<u8>,
  #[napi]
  pub pkey: Vec<u8>
}


#[napi(js_name = "AsyncSigning")]
pub struct JsAsyncSigning {
  rt: Arc<Runtime>
}

#[napi]
impl JsAsyncSigning {

  #[napi]
  pub async fn signature(&self, m: Buffer, sk: Buffer) -> Result<Buffer> {
    compute_in!(self, nacl::sign::signature(&m, &sk))
  }

  #[napi]
  pub async fn verify(&self, sig: Buffer, m: Buffer, pk: Buffer) -> Result<bool> {
    compute_in!(self, nacl::sign::verify(&sig, &m, &pk))
  }

  #[napi]
  pub async fn generate_keypair(&self, seed: Buffer) -> Result<JsKeypair> {
    let keypair = self.rt.spawn(async move {
      nacl::sign::generate_keypair(&seed)
    }).await.unwrap();
    Ok(JsKeypair {
      skey: Vec::from(keypair.skey),
      pkey: Vec::from(keypair.pkey)
    })
  }

}


#[napi(js_name = "Cryptor")]
pub struct JsCryptor {
  rt: Arc<Runtime>,
  sbox: JsAsyncSBoxCryptor
}

#[napi]
impl JsCryptor {

  #[napi(factory)]
  pub fn make_treaded(max_num_of_threads: u32, thread_name: String) -> Self {
    let threaded_rt = Builder::new_multi_thread()
      .worker_threads(max_num_of_threads.try_into().unwrap())
      .thread_name(thread_name)
      .build()
      .unwrap();
    let rt = Arc::new(threaded_rt);
    let sbox = JsAsyncSBoxCryptor {
      rt: rt.clone(),
      labels: DashMap::new(),
      max_num_of_threads
    };
    JsCryptor { rt, sbox }
  }

  #[napi(getter)]
  pub fn sbox(&self) -> JsAsyncSBoxCryptor {
    self.sbox.clone()
  }

  #[napi(getter)]
  pub fn pbox(&self) -> JsAsyncPBox {
    JsAsyncPBox { rt: self.rt.clone() }
  }

  #[napi(getter)]
  pub fn signing(&self) -> JsAsyncSigning {
    JsAsyncSigning { rt: self.rt.clone() }
  }

  #[napi]
  pub async fn scrypt(
    &self, passwd: Buffer, salt: Buffer, log_n: u8, r: u32, p: u32, dk_len: u32,
    report_progress: ThreadsafeFunction<u32>
  ) -> Result<Buffer> {
    compute_in!(self, {
      let cb = |p: u32| {
        report_progress.call(Ok(p), ThreadsafeFunctionCallMode::Blocking);
      };
      nacl::scrypt(&passwd, &salt, log_n, r as usize, p as usize, dk_len as usize, &cb)
    })
  }

}

#[napi]
pub fn copy_nonce_from_format_w_n(c: Buffer) -> Result<Buffer> {
  match nacl::secret_box::format_wn::copy_nonce_from(&c) {
    Ok(r) => Ok(r.into()),
    Err(err) => Err(Error::from_reason(err.message))
  }
}

#[napi]
pub const SBOX_JWK_ALG_NAME: &str = nacl::secret_box::JWK_ALG_NAME;
#[napi]
pub const SBOX_KEY_LENGTH: u32 = nacl::secret_box::KEY_LENGTH as u32;
#[napi]
pub const SBOX_NONCE_LENGTH: u32 = nacl::secret_box::NONCE_LENGTH as u32;
#[napi]
pub const SBOX_POLY_LENGTH: u32 = nacl::secret_box::POLY_LENGTH as u32;

#[napi]
pub const PBOX_JWK_ALG_NAME: &str = nacl::public_box::JWK_ALG_NAME;
#[napi]
pub const PBOX_KEY_LENGTH: u32 = nacl::public_box::KEY_LENGTH as u32;

#[napi]
pub const SIGNING_JWK_ALG_NAME: &str = nacl::sign::JWK_ALG_NAME;
#[napi]
pub const SIGNING_SEED_LENGTH: u32 = nacl::sign::SEED_LENGTH as u32;
#[napi]
pub const SIGNING_SECRET_KEY_LENGTH: u32 = nacl::sign::SECRET_KEY_LENGTH as u32;
#[napi]
pub const SIGNING_PUBLIC_KEY_LENGTH: u32 = nacl::sign::PUBLIC_KEY_LENGTH as u32;


#[napi]
pub fn plus_five(x: u32) -> u32 {
  x + 5
}
