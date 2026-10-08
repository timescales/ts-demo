import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../../components/testing/a11y';
import { tradeCopy } from './copy';
import { DisclosureChips, enclaveLabel } from './DisclosureChips';

const c = tradeCopy.disclosure;

describe('DisclosureChips', () => {
  it('simulated enclave: readable by the operator, with the plum label', async () => {
    render(<DisclosureChips enclave="simulated" />);
    expect(screen.getByText(c.simulated)).toBeTruthy();
    expect(screen.getByText('Simulated')).toBeTruthy();
    expect(screen.queryByText(c.tdx, { exact: false })).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('TDX vouched by the key committee', async () => {
    render(<DisclosureChips enclave="intel_tdx_vouched" />);
    expect(screen.getByText(c.tdx)).toBeTruthy();
    expect(screen.queryByText(/operator-reported/)).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('TDX as reported by the operator says so', async () => {
    render(<DisclosureChips enclave="operator_reported" />);
    expect(screen.getByText(`${c.tdx} ${c.operatorReported}`)).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('always lists what is public and the linkability of resting orders', () => {
    render(<DisclosureChips enclave="simulated" />);
    for (const text of [c.publicIfFilled, c.alwaysPublic, c.linkable]) {
      expect(screen.getByText(text)).toBeTruthy();
    }
  });

  it('never upgrades an unverified report to verified TDX', () => {
    expect(enclaveLabel(undefined, 'intel_tdx')).toBe('operator_reported');
    expect(enclaveLabel(undefined, 'simulated')).toBe('simulated');
    expect(enclaveLabel(undefined, 'unknown')).toBe('simulated');
    expect(enclaveLabel('intel_tdx_vouched', 'simulated')).toBe('intel_tdx_vouched');
  });
});
