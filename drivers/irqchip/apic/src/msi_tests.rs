//! Host tests for the message a PCI function writes to reach a local APIC.

use super::msi;

#[test]
fn a_message_names_the_destination_in_bits_19_to_12_and_the_vector_in_the_data() {
    assert_eq!(msi::message(0, 48), Some((0xfee0_0000, 48)));
    assert_eq!(msi::message(1, 48), Some((0xfee0_1000, 48)));
    assert_eq!(msi::message(255, 0xfe), Some((0xfeef_f000, 0xfe)));
}

#[test]
fn a_destination_the_address_cannot_carry_is_refused_not_truncated() {
    // 256 would be written as APIC 0: some other CPU's interrupt.
    assert_eq!(msi::message(256, 48), None);
    assert_eq!(msi::message(u32::MAX, 48), None);
}

#[test]
fn an_exception_vector_is_refused() {
    assert_eq!(msi::message(0, 0), None);
    assert_eq!(msi::message(0, 31), None);
    assert!(msi::message(0, 32).is_some());
}

#[test]
fn a_message_decodes_back_to_its_destination_and_vector() {
    for id in [0, 1, 7, 255] {
        for vector in [32, 48, 63, 0xef] {
            let (address, data) = msi::message(id, vector).unwrap();
            assert_eq!(msi::destination(address), Some(id));
            assert_eq!(msi::vector(data), Some(vector));
        }
    }
    assert_eq!(msi::destination(0xfec0_0000), None, "an I/O APIC's window");
    assert_eq!(msi::destination(0x1_fee0_0000), None, "above 4 GiB");
    assert_eq!(msi::vector(0x100 | 48), None, "lowest-priority delivery");
    assert_eq!(msi::vector(0x8000 | 48), None, "level-triggered");
}
