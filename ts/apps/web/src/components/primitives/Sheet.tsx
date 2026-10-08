import type { ModalProps } from './ModalSurface';
import { ModalSurface } from './ModalSurface';

export type SheetProps = ModalProps;

/** A modal sheet anchored to the bottom edge (deposits, withdrawals, the mobile ticket). */
export function Sheet(props: SheetProps) {
  return <ModalSurface placement="bottom" {...props} />;
}
