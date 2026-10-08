//! The upgradeable loader's `ProgramData` account of the settlement program:
//! who can upgrade it and when it was last deployed (V-16). A program
//! upgrade bypasses every market timelock, so clients show both.

use crate::program::pda::find_pda;
use crate::program::{BPF_LOADER_UPGRADEABLE, ClientError, Key};

/// `UpgradeableLoaderState::ProgramData` header: `3 u32 || slot u64 ||
/// Option<authority>`, followed by the program's ELF.
const PROGRAM_DATA_METADATA_LEN: usize = 45;
const PROGRAM_DATA_TAG: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramData {
    /// Slot of the last deployment or upgrade.
    pub last_deploy_slot: u64,
    /// `None` once the program is immutable.
    pub upgrade_authority: Option<Key>,
}

/// The `ProgramData` account of an upgradeable `program`: `[program]`
/// derived by the upgradeable loader.
pub fn program_data_address(program: &Key) -> Result<Key, ClientError> {
    Ok(find_pda(&[program], &BPF_LOADER_UPGRADEABLE)?.0)
}

/// Decodes the metadata of a `ProgramData` account (bincode, as the loader
/// writes it). Clearing the authority writes only the `None` tag, so the 32
/// bytes after it are ignored then.
pub fn decode_program_data(d: &[u8]) -> Result<ProgramData, ClientError> {
    let meta: &[u8; PROGRAM_DATA_METADATA_LEN] = d
        .get(..PROGRAM_DATA_METADATA_LEN)
        .and_then(|m| m.try_into().ok())
        .ok_or(ClientError::Malformed)?;
    let (tag, rest) = meta.split_at(4);
    let (slot, rest) = rest.split_at(8);
    let (option, key) = rest.split_at(1);
    if tag != PROGRAM_DATA_TAG.to_le_bytes() {
        return Err(ClientError::Malformed);
    }
    let upgrade_authority = match option[0] {
        0 => None,
        1 => Some(key.try_into().map_err(|_| ClientError::Malformed)?),
        _ => return Err(ClientError::Malformed),
    };
    Ok(ProgramData {
        last_deploy_slot: u64::from_le_bytes(slot.try_into().map_err(|_| ClientError::Malformed)?),
        upgrade_authority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_data(slot: u64, authority: Option<Key>, elf: &[u8]) -> Vec<u8> {
        let mut d = 3u32.to_le_bytes().to_vec();
        d.extend_from_slice(&slot.to_le_bytes());
        d.push(u8::from(authority.is_some()));
        d.extend_from_slice(&authority.unwrap_or([0x5c; 32]));
        d.extend_from_slice(elf);
        d
    }

    #[test]
    fn program_data_with_and_without_an_authority() {
        let d = program_data(77, Some([9; 32]), b"\x7fELF");
        assert_eq!(
            decode_program_data(&d).unwrap(),
            ProgramData {
                last_deploy_slot: 77,
                upgrade_authority: Some([9; 32]),
            }
        );
        let d = program_data(5, None, &[]);
        assert_eq!(decode_program_data(&d).unwrap().upgrade_authority, None);
    }

    #[test]
    fn other_loader_states_and_short_data_are_refused() {
        let mut program = program_data(1, None, &[]);
        program[0] = 2;
        assert!(decode_program_data(&program).is_err());
        let mut bad_option = program_data(1, None, &[]);
        bad_option[12] = 2;
        assert!(decode_program_data(&bad_option).is_err());
        assert!(decode_program_data(&program_data(1, None, &[])[..44]).is_err());
    }
}
