// tests/layout.test.js — run: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('../app/layout.js');

const W = (type, x, y, w, h) => ({ type, x, y, w, h });
const overlapFree = items => items.every((a, i) => items.every((b, j) => i === j || !L.collides(a, b)));

test('catalogue matches the server copy', () => {
  assert.deepEqual(Object.keys(L.WIDGETS).sort(), ['alerts', 'donut', 'kpis', 'map', 'rate', 'resources', 'rules', 'trend']);
  assert.equal(L.WIDGETS.map.minW, 5); assert.equal(L.WIDGETS.map.minH, 8);
  assert.equal(L.WIDGETS.alerts.wallSafe, false); assert.equal(L.WIDGETS.map.wallSafe, 'anon');
});

test('collides only on real overlap', () => {
  assert.equal(L.collides(W('a', 0, 0, 6, 4), W('b', 6, 0, 6, 4)), false);   // touching edges
  assert.equal(L.collides(W('a', 0, 0, 6, 4), W('b', 5, 3, 6, 4)), true);
});

test('dropping a widget onto another pushes the other down, no overlaps, no gaps', () => {
  const items = [W('map', 0, 0, 8, 10), W('donut', 8, 0, 4, 6)];
  const out = L.move(items, 1, 4, 2);                        // drag donut onto the map
  assert.ok(overlapFree(out));
  const donut = out.find(i => i.type === 'donut'), map = out.find(i => i.type === 'map');
  assert.deepEqual([donut.x, donut.y], [4, 0]);              // compacted up to the top
  assert.equal(map.y, donut.h);                               // map pushed below it
  assert.deepEqual(items[1], W('donut', 8, 0, 4, 6));         // input untouched
});

test('move clamps to the grid and resize respects minimums', () => {
  const items = [W('map', 0, 0, 8, 10)];
  assert.equal(L.move(items, 0, 11, 0)[0].x, 4);             // 4 + 8 = 12
  const r = L.resize(items, 0, 2, 1)[0];
  assert.deepEqual([r.w, r.h], [5, 8]);
  assert.equal(L.resize(items, 0, 20, 10)[0].w, 12);
});

test('compact removes vertical gaps but keeps horizontal order', () => {
  const out = L.compact([W('kpis', 0, 5, 12, 4), W('map', 0, 20, 6, 8), W('donut', 6, 30, 6, 6)]);
  assert.deepEqual(out.map(i => [i.type, i.y]), [['kpis', 0], ['map', 4], ['donut', 4]]);
});

test('addWidget appends at the bottom with the default size; removeWidget compacts', () => {
  let items = [W('kpis', 0, 0, 12, 4)];
  items = L.addWidget(items, 'resources');
  const r = items.find(i => i.type === 'resources');
  assert.deepEqual([r.x, r.y, r.w, r.h], [0, 4, L.WIDGETS.resources.w, L.WIDGETS.resources.h]);
  assert.throws(() => L.addWidget(items, 'resources'), /already/);
  items = L.removeWidget(items, 0);
  assert.equal(items[0].y, 0);
});

test('readingOrder sorts by row then column', () => {
  assert.deepEqual(L.readingOrder([W('b', 6, 0, 6, 4), W('c', 0, 4, 12, 4), W('a', 0, 0, 6, 4)]).map(i => i.type), ['a', 'b', 'c']);
});

test('sanitizeLayout drops unknown types with a note', () => {
  const { layout, notes } = L.sanitizeLayout({ schema: 1, version: 3, screens: [{ id: 's', name: 'S', wall: true, widgets: [W('map', 0, 0, 12, 10), W('hologram', 0, 10, 4, 4)] }] });
  assert.deepEqual(layout.screens[0].widgets.map(w => w.type), ['map']);
  assert.match(notes[0], /hologram/);
});

test('isPersonalStale when the shared layout moved on', () => {
  assert.equal(L.isPersonalStale({ baseVersion: 2 }, { version: 2 }), false);
  assert.equal(L.isPersonalStale({ baseVersion: 2 }, { version: 3 }), true);
});

test('screens: add, rename, move, remove (never the last one)', () => {
  let lay = { schema: 1, version: 0, screens: [{ id: 'a', name: 'A', wall: false, widgets: [] }] };
  lay = L.addScreen(lay, 'Threats');
  assert.deepEqual(lay.screens.map(s => s.id), ['a', 'threats']);
  lay = L.renameScreen(lay, 'threats', '  Hunting  ');
  assert.equal(lay.screens[1].name, 'Hunting');
  lay = L.moveScreen(lay, 'threats', -1);
  assert.deepEqual(lay.screens.map(s => s.id), ['threats', 'a']);
  lay = L.removeScreen(lay, 'a');
  assert.deepEqual(lay.screens.map(s => s.id), ['threats']);
  assert.throws(() => L.removeScreen(lay, 'threats'), /last screen/);
});

test('moving a widget down onto the one below swaps them (keyboard ArrowDown is not a no-op)', () => {
  const ws = [W('kpis', 0, 0, 12, 4), W('donut', 8, 4, 4, 6), W('rules', 8, 10, 4, 8)];
  const out = L.move(ws, 1, 8, 5);
  const donut = out.find(i => i.type === 'donut'), rules = out.find(i => i.type === 'rules');
  assert.ok(donut.y > rules.y, 'donut ends below rules');
  assert.equal(rules.y, 4);
  assert.ok(overlapFree(out));
});
