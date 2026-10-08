import type { ModalProps } from './ModalSurface';
import { ModalSurface } from './ModalSurface';

export type DrawerProps = ModalProps;

/** A modal panel on the right edge. A bottom sheet below 600 px. */
export function Drawer(props: DrawerProps) {
  return <ModalSurface placement="side" {...props} />;
}
