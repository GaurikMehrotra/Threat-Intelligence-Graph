'use strict';
const $ = id => document.getElementById(id);
const NS = 'http://www.w3.org/2000/svg';
let selected = null, data = {nodes: [], edges: []}, transform = {x: 0, y: 0, scale: 1};
let generation = 0;
function status(message) { $('status').textContent = message; }
async function get(url) {
  const response = await fetch(url, {credentials: 'same-origin'});
  if (!response.ok) throw new Error(`Request failed (${response.status}). Check filters or retry.`);
  return response.json();
}
function svg(tag, attributes, text) {
  const element = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attributes || {})) element.setAttribute(key, String(value));
  if (text !== undefined) element.textContent = text;
  return element;
}
function detail(title, value) {
  $('detail-title').textContent = title;
  $('details').replaceChildren();
  const pre = document.createElement('pre'); pre.textContent = JSON.stringify(value, null, 2);
  $('details').append(pre);
}
async function edgeDetail(edge) {
  try { detail('Relationship, evidence, and confidence', await get(`/api/edges/${encodeURIComponent(edge.edge_id)}`)); }
  catch (error) { status(error.message); }
}
async function selectNode(node) {
  selected = node.node_id; $('expand').disabled = false;
  try { detail(`${node.entity_type}: ${node.display_name}`, await get(`/api/nodes/${encodeURIComponent(node.node_id)}`)); }
  catch (error) { status(error.message); }
}
function updateTransform() { $('viewport').setAttribute('transform', `translate(${transform.x} ${transform.y}) scale(${transform.scale})`); }
function draw() {
  const viewport = $('viewport'); viewport.replaceChildren();
  $('empty').hidden = data.nodes.length > 0;
  const positions = new Map();
  const count = data.nodes.length;
  // Deterministic concentric layout avoids an unbounded force simulation.
  data.nodes.forEach((node, i) => {
    const ring = Math.floor(i / 24), inRing = i % 24, size = Math.min(24, count - ring * 24);
    const angle = 2 * Math.PI * inRing / Math.max(1, size);
    const radius = count === 1 ? 0 : 150 + ring * 90;
    positions.set(node.node_id, {x: 500 + radius * Math.cos(angle), y: 350 + radius * Math.sin(angle)});
  });
  $('edge-list').replaceChildren();
  data.edges.forEach(edge => {
    const a = positions.get(edge.source_node_id), b = positions.get(edge.target_node_id);
    if (!a || !b) return;
    const origin = edge.relationship_origin;
    const line = svg('line', {x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'graph-edge',
      stroke: edge.status === 'disputed' ? '#f2b07a' : '#819eb7',
      'stroke-dasharray': origin === 'hypothesis' ? '2 6' : origin === 'direct_observation' ? '' : '8 4', tabindex: 0});
    line.append(svg('title', {}, `${edge.relationship_type} (${origin}; ${edge.status})`));
    line.addEventListener('click', () => edgeDetail(edge));
    line.addEventListener('keydown', e => {if(e.key === 'Enter') edgeDetail(edge);});
    viewport.append(line);
    if (data.edges.length <= 60) viewport.append(svg('text', {x: (a.x+b.x)/2, y: (a.y+b.y)/2}, edge.relationship_type));
    const button = document.createElement('button');
    button.textContent = `${edge.relationship_type} · ${origin} · ${edge.status}`;
    button.addEventListener('click', () => edgeDetail(edge)); $('edge-list').append(button);
  });
  data.nodes.forEach(node => {
    const pos = positions.get(node.node_id);
    const group = svg('g', {class: 'graph-node', tabindex: 0, role: 'button', 'aria-label': `${node.entity_type}: ${node.display_name}`, transform: `translate(${pos.x} ${pos.y})`});
    const type = node.entity_type;
    let shape;
    if (['process','file','malware_sample'].includes(type)) shape = svg('rect', {x:-12,y:-12,width:24,height:24,fill:'#75c7b6'});
    else if (['threat_actor','campaign'].includes(type)) shape = svg('polygon', {points:'0,-15 15,0 0,15 -15,0',fill:'#e5ba6c'});
    else if (['attack_technique','attack_tactic','source','investigation'].includes(type)) shape = svg('polygon', {points:'0,-15 14,12 -14,12',fill:'#bba2dc'});
    else shape = svg('circle', {r:11,fill:'#79b8e8'});
    shape.setAttribute('stroke', node.node_id === selected ? '#fff' : '#101820');
    shape.setAttribute('stroke-width', '2'); group.append(shape);
    group.append(svg('text', {x:16,y:4}, `${type}: ${node.display_name.slice(0,38)}`));
    group.append(svg('title', {}, node.display_name));
    group.addEventListener('click', () => selectNode(node));
    group.addEventListener('dblclick', () => {selected=node.node_id; loadGraph();});
    group.addEventListener('keydown', e => {if(e.key === 'Enter') selectNode(node);});
    viewport.append(group);
  });
  updateTransform();
}
async function loadGraph() {
  if (!selected) return;
  const current = ++generation;
  status('Loading bounded neighborhood…');
  const params = new URLSearchParams({node:selected,depth:$('depth').value,limit:$('limit').value,include_unknown:$('unknown').checked});
  if ($('entity').value) params.append('entity_type', $('entity').value);
  if ($('relationship').value) params.append('relationship_type', $('relationship').value);
  for (const key of ['after','before']) if ($(key).value) params.append(key, new Date($(key).value).toISOString());
  try {
    const result = await get(`/api/neighborhood?${params}`);
    if (current !== generation) return;
    data = result; draw();
    status(`${data.nodes.length} entities · ${data.edges.length} claims${data.truncated ? ' · Truncated: refine filters' : ''}`);
  } catch (error) { if(current === generation) status(error.message); }
}
$('search').addEventListener('submit', async event => {
  event.preventDefault(); status('Searching…'); $('results').replaceChildren();
  try {
    const query = $('query').value;
    const results = /^node_[a-f0-9]{64}$/.test(query) ? [await get(`/api/nodes/${query}`)] : await get(`/api/search?${new URLSearchParams({value:query,limit:50})}`);
    status(results.length ? `${results.length} matching entities (up to 50)` : 'No matching entities. Import records with the CLI first.');
    results.forEach(node => {
      const button = document.createElement('button'); button.textContent = `${node.entity_type}: ${node.display_name}`;
      button.addEventListener('click', () => {selectNode(node); loadGraph();}); $('results').append(button);
    });
  } catch (error) {status(error.message);}
});
$('expand').addEventListener('click', loadGraph);
$('fit').addEventListener('click', () => {transform={x:0,y:0,scale:1}; updateTransform();});
const graph = $('graph'); let drag = null;
graph.addEventListener('wheel', event => {event.preventDefault();transform.scale=Math.max(.15,Math.min(5,transform.scale*(event.deltaY<0?1.1:.9)));updateTransform();}, {passive:false});
graph.addEventListener('pointerdown', event => {if(event.target.closest('.graph-node,.graph-edge')) return;drag={x:event.clientX,y:event.clientY};graph.setPointerCapture(event.pointerId);});
graph.addEventListener('pointermove', event => {if(!drag)return;const rect=graph.getBoundingClientRect();transform.x+=(event.clientX-drag.x)*1000/rect.width;transform.y+=(event.clientY-drag.y)*700/rect.height;drag={x:event.clientX,y:event.clientY};updateTransform();});
graph.addEventListener('pointerup',()=>{drag=null;});
$('open-case').addEventListener('click',async()=>{
  const id=$('investigation').value;if(!id){status('Select a saved investigation.');return;}
  try{data=await get(`/api/investigations/${id}/export`);draw();status(`Investigation: ${data.nodes.length} entities${data.truncated?' · truncated':''}`);}catch(error){status(error.message);}
});
for(const format of ['json','md']) $('export-'+format).addEventListener('click',async()=>{
  const id=$('investigation').value;if(!id){status('Select an investigation. Create one with the CLI.');return;}
  try{const response=await fetch(`/api/investigations/${id}/export?format=${format}`);if(!response.ok)throw new Error('Export failed.');const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download=`investigation.${format}`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){status(error.message);}
});
(async()=>{
  try{
    const [schema,cases,stats]=await Promise.all([get('/api/schema'),get('/api/investigations'),get('/api/stats')]);
    for(const type of schema.entity_types){const option=document.createElement('option');option.value=type;option.textContent=type;$('entity').append(option);}
    for(const type of Object.keys(schema.relationships)){const option=document.createElement('option');option.value=type;option.textContent=type;$('relationship').append(option);}
    for(const item of cases){const option=document.createElement('option');option.value=item.node_id;option.textContent=item.display_name;$('investigation').append(option);}
    status(`${stats.nodes} entities · ${stats.edges} evidence-backed claims. Search to begin.`);
  }catch(error){status(error.message);}
})();
