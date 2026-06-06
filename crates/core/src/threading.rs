/// Marker used by portable async traits to switch between native threaded
/// runtimes and Worker-style local futures.
///
/// Without `local-futures`, public async ports retain `Send + Sync` and
/// `Future + Send` compatibility for native web runtimes. With
/// `local-futures`, the marker imposes no thread-safety bound so Worker
/// adapters can use local bindings and `!Send` futures.
#[cfg(not(feature = "local-futures"))]
pub trait RuntimeSendSync: Send + Sync {}

#[cfg(not(feature = "local-futures"))]
impl<T: ?Sized + Send + Sync> RuntimeSendSync for T {}

#[cfg(feature = "local-futures")]
pub trait RuntimeSendSync {}

#[cfg(feature = "local-futures")]
impl<T: ?Sized> RuntimeSendSync for T {}
