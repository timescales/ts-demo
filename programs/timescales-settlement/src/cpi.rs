//! System and SPL Token calls, PDA creation and closing, token-account
//! validation. Instructions are encoded by hand so the program depends
//! only on `solana-program`.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

use crate::error::TimescalesError;
use crate::processor::require;

pub const TOKEN_PROGRAM: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const SYSTEM_PROGRAM: Pubkey = solana_program::pubkey!("11111111111111111111111111111111");

pub const MINT_LEN: usize = 82;
pub const TOKEN_ACCOUNT_LEN: usize = 165;

fn system_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts,
        data,
    }
}

/// `SystemInstruction` in its bincode layout: a u32 variant, then fields.
fn system_data(variant: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut d = variant.to_le_bytes().to_vec();
    for f in fields {
        d.extend_from_slice(f);
    }
    d
}

/// The canonical bump of the PDA `seeds`, which `target` must be.
pub fn pda_bump(
    program_id: &Pubkey,
    target: &AccountInfo,
    seeds: &[&[u8]],
) -> Result<u8, ProgramError> {
    let (expected, bump) = Pubkey::find_program_address(seeds, program_id);
    require(*target.key == expected, TimescalesError::InvalidAccount)?;
    Ok(bump)
}

/// Creates the PDA `seeds || bump` owned by this program with `space`
/// zeroed bytes, or adopts it if someone already sent it lamports: a
/// System-owned, data-less account is topped up to rent exemption,
/// allocated and assigned, all signed by the PDA, so nobody but the program
/// can pre-allocate it. `bump` comes from [`pda_bump`].
pub fn init_pda<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: u8,
    space: usize,
) -> ProgramResult {
    require(
        *system.key == SYSTEM_PROGRAM,
        TimescalesError::InvalidAccount,
    )?;
    let bump_seed = [bump];
    let mut signer: Vec<&[u8]> = seeds.to_vec();
    signer.push(&bump_seed);
    let signer = [signer.as_slice()];
    let rent = Rent::get()?.minimum_balance(space);
    let space_le = (space as u64).to_le_bytes();
    let owner = program_id.to_bytes();
    let infos = [payer.clone(), target.clone(), system.clone()];

    if target.lamports() == 0 {
        let ix = system_ix(
            vec![
                AccountMeta::new(*payer.key, true),
                AccountMeta::new(*target.key, true),
            ],
            system_data(0, &[&rent.to_le_bytes(), &space_le, &owner]),
        );
        return invoke_signed(&ix, &infos, &signer);
    }

    require(
        *target.owner == SYSTEM_PROGRAM && target.data_is_empty(),
        TimescalesError::InvalidAccount,
    )?;
    let missing = rent.saturating_sub(target.lamports());
    if missing > 0 {
        let ix = system_ix(
            vec![
                AccountMeta::new(*payer.key, true),
                AccountMeta::new(*target.key, false),
            ],
            system_data(2, &[&missing.to_le_bytes()]),
        );
        invoke(&ix, &infos)?;
    }
    let allocate = system_ix(
        vec![AccountMeta::new(*target.key, true)],
        system_data(8, &[&space_le]),
    );
    invoke_signed(&allocate, &infos, &signer)?;
    let assign = system_ix(
        vec![AccountMeta::new(*target.key, true)],
        system_data(1, &[&owner]),
    );
    invoke_signed(&assign, &infos, &signer)
}

/// Moves every lamport to `dest`, zeroes the data, shrinks it to zero and
/// hands the account back to the System program, so an account that is
/// sent lamports later in the same transaction can still be re-created.
pub fn close_account(acc: &AccountInfo, dest: &AccountInfo) -> ProgramResult {
    let lamports = acc.lamports();
    let credited = dest
        .lamports()
        .checked_add(lamports)
        .ok_or(TimescalesError::Overflow)?;
    **dest.try_borrow_mut_lamports()? = credited;
    **acc.try_borrow_mut_lamports()? = 0;
    acc.try_borrow_mut_data()?.fill(0);
    acc.resize(0)?;
    acc.assign(&SYSTEM_PROGRAM);
    Ok(())
}

/// A classic SPL Token mint: owned by Token, 82 bytes, initialized.
pub fn check_mint(acc: &AccountInfo) -> ProgramResult {
    require(
        *acc.owner == TOKEN_PROGRAM,
        TimescalesError::InvalidTokenAccount,
    )?;
    let d = acc.try_borrow_data()?;
    require(
        d.len() == MINT_LEN && d[45] == 1,
        TimescalesError::InvalidTokenAccount,
    )
}

/// A classic SPL Token account in the initialized state. Returns
/// `(mint, owner)`.
pub fn token_account(acc: &AccountInfo) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    require(
        *acc.owner == TOKEN_PROGRAM,
        TimescalesError::InvalidTokenAccount,
    )?;
    let d = acc.try_borrow_data()?;
    require(
        d.len() == TOKEN_ACCOUNT_LEN && d[108] == 1,
        TimescalesError::InvalidTokenAccount,
    )?;
    let mut mint = [0u8; 32];
    let mut owner = [0u8; 32];
    mint.copy_from_slice(&d[..32]);
    owner.copy_from_slice(&d[32..64]);
    Ok((mint, owner))
}

/// A vault: a token account of `mint` owned by `market`, with no delegate
/// (COption tag at 72..76 is zero) and no close authority (tag at 129..133).
pub fn check_vault(acc: &AccountInfo, mint: &Pubkey, market: &Pubkey) -> ProgramResult {
    let (m, owner) = token_account(acc)?;
    require(
        m == mint.to_bytes() && owner == market.to_bytes(),
        TimescalesError::InvalidTokenAccount,
    )?;
    let d = acc.try_borrow_data()?;
    require(
        d[72..76] == [0; 4] && d[129..133] == [0; 4],
        TimescalesError::InvalidTokenAccount,
    )
}

/// SPL Token `Transfer`, signed by `authority` (or by the PDA `signer`).
pub fn token_transfer<'a>(
    token: &AccountInfo<'a>,
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    signer: Option<&[&[u8]]>,
) -> ProgramResult {
    require(*token.key == TOKEN_PROGRAM, TimescalesError::InvalidAccount)?;
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    let infos = [from.clone(), to.clone(), authority.clone(), token.clone()];
    match signer {
        Some(s) => invoke_signed(&ix, &infos, &[s]),
        None => invoke(&ix, &infos),
    }
}
