import type { TapeRow } from '@timescales/sdk/api';
import type { BookId, UnitContext } from '@timescales/sdk/core';
import type { KeyboardEvent } from 'react';
import { useId, useRef, useState } from 'react';

import { componentsCopy } from '../../components/copy';
import { tradeCopy } from './copy';
import type { NumberFormat } from './services';
import styles from './trade.module.css';
import { localize, priceOf } from './units';

export interface ClearingChartProps {
  pair: string;
  bookLabel: string;
  book: BookId;
  /** Newest first, as the tape serves them. */
  rows: readonly TapeRow[];
  units: UnitContext;
  numberFormat: NumberFormat;
  /** Epochs (decimal strings) in which this wallet's orders filled. Local only. */
  ownFillEpochs: ReadonlySet<string>;
  onOpenEpoch: (epoch: bigint) => void;
  /** Id of the tape, its table alternative. */
  tableId: string;
}

const W = 640;
const H = 220;
const PAD = { top: 16, right: 16, bottom: 48, left: 16 };
const VOLUME_H = 32;

interface Point {
  row: TapeRow;
  tick: bigint | null;
  volume: bigint;
}

/**
 * Step line of the uniform clearing price per epoch for one book, matched
 * volume bars and own fills as seal markers. Each epoch is a labelled
 * button. Arrow keys move between them and Enter opens the epoch.
 */
export function ClearingChart({
  pair,
  bookLabel,
  book,
  rows,
  units,
  numberFormat,
  ownFillEpochs,
  onOpenEpoch,
  tableId,
}: ClearingChartProps) {
  const copy = tradeCopy.chart;
  const hintId = useId();
  const [active, setActive] = useState(0);
  const refs = useRef<(SVGGElement | null)[]>([]);
  const points: Point[] = [...rows].reverse().map((row) => {
    const c = row.clearing.find((x) => x.book === book);
    return { row, tick: c?.tick ?? null, volume: c?.volume ?? 0n };
  });
  const ticks = points.flatMap((p) => (p.tick === null ? [] : [p.tick]));
  const lo = ticks.reduce<bigint | null>((m, t) => (m === null || t < m ? t : m), null);
  const hi = ticks.reduce<bigint | null>((m, t) => (m === null || t > m ? t : m), null);
  const maxVolume = points.reduce((m, p) => (p.volume > m ? p.volume : m), 0n);
  const price = (tick: bigint) => localize(priceOf(units, tick), numberFormat);

  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom - VOLUME_H;
  const step = points.length > 0 ? plotW / points.length : plotW;
  const x = (i: number) => PAD.left + step * i;
  const y = (tick: bigint) => {
    if (lo === null || hi === null || hi === lo) return PAD.top + plotH / 2;
    return PAD.top + plotH - (Number(tick - lo) / Number(hi - lo)) * plotH;
  };

  let path = '';
  points.forEach((p, i) => {
    if (p.tick === null) return;
    const prev = points[i - 1];
    path += `${prev?.tick != null ? 'L' : 'M'}${x(i)},${y(p.tick)}H${x(i) + step}`;
  });

  const summary = copy.summary(
    pair,
    bookLabel,
    points.length,
    lo === null ? '' : price(lo),
    hi === null ? '' : price(hi),
  );
  const current = Math.min(active, Math.max(0, points.length - 1));

  const move = (to: number) => {
    const next = Math.max(0, Math.min(points.length - 1, to));
    setActive(next);
    refs.current[next]?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<SVGGElement>, i: number) => {
    const p = points[i];
    if (event.key === 'ArrowRight' || event.key === 'ArrowUp') move(i + 1);
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowDown') move(i - 1);
    else if (event.key === 'Home') move(0);
    else if (event.key === 'End') move(points.length - 1);
    else if ((event.key === 'Enter' || event.key === ' ') && p) onOpenEpoch(p.row.epoch);
    else return;
    event.preventDefault();
  };

  return (
    <figure className={styles.chart}>
      <figcaption className={styles.chartCaption}>
        <h2>{copy.title}</h2>
        <a href={`#${tableId}`}>{copy.viewTable}</a>
      </figcaption>
      <div
        role="group"
        aria-roledescription="chart"
        aria-label={summary}
        aria-describedby={hintId}
        className={styles.chartFrame}
      >
        <svg viewBox={`0 0 ${W} ${H}`} className={styles.chartSvg} focusable="false">
          <path d={path} className={styles.chartLine} aria-hidden="true" />
          {points.map((p, i) => {
            const cx = x(i) + step / 2;
            const fill = ownFillEpochs.has(p.row.epoch.toString());
            const barH = maxVolume > 0n ? (Number(p.volume) / Number(maxVolume)) * VOLUME_H : 0;
            const label =
              p.tick === null
                ? copy.pointNoClear(
                    p.row.epoch.toString(),
                    p.row.phase === 'unknown' ? '' : componentsCopy.phase[p.row.phase],
                  )
                : copy.point(p.row.epoch.toString(), price(p.tick), p.row.fillCount) +
                  (fill ? `, ${copy.ownFill}` : '');
            return (
              <g
                key={p.row.epoch.toString()}
                ref={(el) => {
                  refs.current[i] = el;
                }}
                role="button"
                tabIndex={i === current ? 0 : -1}
                aria-label={label}
                className={styles.chartPoint}
                onKeyDown={(event) => onKeyDown(event, i)}
                onClick={() => onOpenEpoch(p.row.epoch)}
                onFocus={() => setActive(i)}
              >
                <rect
                  x={x(i)}
                  y={PAD.top}
                  width={step}
                  height={H - PAD.top - PAD.bottom / 2}
                  className={styles.chartHit}
                />
                <rect
                  x={x(i) + step * 0.2}
                  y={H - PAD.bottom / 2 - barH}
                  width={step * 0.6}
                  height={barH}
                  className={styles.chartBar}
                />
                {p.tick !== null ? (
                  <circle cx={cx} cy={y(p.tick)} r={3} className={styles.chartDot} />
                ) : null}
                {fill && p.tick !== null ? (
                  <circle cx={cx} cy={y(p.tick)} r={7} className={styles.chartSeal} />
                ) : null}
              </g>
            );
          })}
        </svg>
      </div>
      <p id={hintId} className={styles.hint}>
        {copy.keyboardHint}
      </p>
    </figure>
  );
}
