pub mod binding;
pub use binding::*;

#[cfg(test)]
mod test {
    use crate::OIDN_DEVICE_TYPE_CPU;

    #[test]
    fn create_device() {
        unsafe {
            use crate::*;
            let device = oidnNewDevice(OIDN_DEVICE_TYPE_CPU);
            oidnCommitDevice(device);
            oidnReleaseDevice(device);
        }
    }
}