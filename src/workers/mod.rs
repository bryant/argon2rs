#[cfg(feature = "scoped_threadpool")]
pub use self::threadpool::*;

#[cfg(feature = "scoped_threadpool")]
mod threadpool;

#[cfg(not(feature = "scoped_threadpool"))]
pub use self::no_threadpool::*;

#[cfg(not(feature = "scoped_threadpool"))]
mod no_threadpool;
