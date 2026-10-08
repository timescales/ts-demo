import type { ComponentType } from 'react';

import { galleryCopy } from './copy';
import { PlaceholderPage } from './PlaceholderPage';

// The gallery itself lives with the components (src/components/gallery/,
// default export of Gallery.tsx). Until it exists the route says so.
const modules = import.meta.glob<{ default: ComponentType }>('../components/gallery/Gallery.tsx');

function MissingGallery() {
  return <PlaceholderPage title={galleryCopy.title} body={galleryCopy.missing} />;
}

export async function loadGallery(): Promise<ComponentType> {
  const load = modules['../components/gallery/Gallery.tsx'];
  return load ? (await load()).default : MissingGallery;
}
