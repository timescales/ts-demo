import type { ModalProps } from './ModalSurface';
import { ModalSurface } from './ModalSurface';

export type DialogProps = ModalProps;

/** A centred modal dialog for confirmations and short forms. */
export function Dialog(props: DialogProps) {
  return <ModalSurface placement="center" {...props} />;
}
