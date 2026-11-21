const crypto = require('node:crypto');

const SESSION_DAYS = 7;
const MAX_JSON = 1_000_000;
const MAX_FILE = 20 * 1024 * 1024;
const MAX_AVATAR = 5 * 1024 * 1024;
const KINDS = new Set(['tasks', 'reminders', 'meetings', 'updates', 'goals']);
const FILE_TYPES = new Set(['pdf','txt','md','csv','json','js','ts','jsx','tsx','py','html','css','sql','java','go','rs','doc','docx','xls','xlsx','ppt','pptx','png','jpg','jpeg','gif','webp','zip']);
const IMAGE_TYPES = new Map([['.jpg','image/jpeg'],['.jpeg','image/jpeg'],['.png','image/png'],['.webp','image/webp']]);

function send(res, status, value, headers = {}) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
  res.statusCode = status;
  res.setHeader('Content-Length', body.length);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  for (const [key, val] of Object.entries(headers)) res.setHeader(key, val);
  if (!Buffer.isBuffer(value)) res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(body);
}

function config() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw Object.assign(new Error('The hosted workspace database is not configured yet. Add SUPABASE_URL and SUPABASE_SECRET_KEY in Vercel, then redeploy.'), { status: 503 });
  return { url: url.replace(/\/+$/, ''), key };
}

async function rest(table, query = '', method = 'GET', body, prefer = '') {
  const { url, key } = config();
  const headers = { apikey: key, Accept: 'application/json' };
  if (!key.startsWith('sb_secret_')) headers.Authorization = `Bearer ${key}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (prefer) headers.Prefer = prefer;
  const response = await fetch(`${url}/rest/v1/${table}${query ? `?${query}` : ''}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let result = null;
  try { result = text ? JSON.parse(text) : null; } catch { result = null; }
  if (!response.ok) {
    const message = response.status === 409 ? 'That email or item already exists.' : 'The hosted database request failed. Check the Supabase schema and Vercel environment variables.';
    throw Object.assign(new Error(message), { status: response.status === 409 ? 409 : 502 });
  }
  return result;
}

function eq(name, value) { return `${name}=eq.${encodeURIComponent(String(value))}`; }
function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), 310000, 32, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}
function passwordMatches(password, stored) {
  try {
    const [salt, expected] = String(stored).split(':');
    const actual = Buffer.from(passwordHash(password, salt).split(':')[1], 'hex');
    const compare = Buffer.from(expected, 'hex');
    return actual.length === compare.length && crypto.timingSafeEqual(actual, compare);
  } catch { return false; }
}
function cookieValue(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return '';
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function publicUser(user) {
  return { id:user.id, name:user.name, email:user.email, role:user.role, active:user.active !== false, avatar:user.avatar_path ? `/api/avatar?id=${encodeURIComponent(user.id)}` : '' };
}
async function currentUser(req) {
  const token = cookieValue(req, 'gather_session');
  if (!token) return null;
  const rows = await rest('sessions', `${eq('token_hash', tokenHash(token))}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=user_id`);
  if (!rows?.length) return null;
  const users = await rest('team_users', `${eq('id', rows[0].user_id)}&active=eq.true&select=*`);
  return users?.[0] || null;
}
async function requireUser(req, res) {
  const user = await currentUser(req);
  if (!user) { send(res, 401, { error:'Please sign in to continue.' }); return null; }
  return user;
}
function validOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
async function jsonBody(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_JSON) throw Object.assign(new Error('That request is too large.'), { status:413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw Object.assign(new Error('Please enter valid details.'), { status:400 }); }
}
async function rawBody(req, maxBytes) {
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('The uploaded file is too large.'), { status:413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
async function multipart(req, maxBytes) {
  const type = req.headers['content-type'] || '';
  const match = type.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!match) throw Object.assign(new Error('Choose a file to upload.'), { status:400 });
  const boundary = Buffer.from(`--${(match[1] || match[2]).trim()}`);
  const body = await rawBody(req, maxBytes);
  const parts = new Map();
  let cursor = 0;
  while (true) {
    const start = body.indexOf(boundary, cursor);
    if (start < 0) break;
    let partStart = start + boundary.length;
    if (body.subarray(partStart, partStart+2).toString() === '--') break;
    if (body.subarray(partStart, partStart+2).toString() === '\r\n') partStart += 2;
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), partStart);
    if (headerEnd < 0) break;
    const headers = body.subarray(partStart, headerEnd).toString('utf8');
    const next = body.indexOf(boundary, headerEnd+4);
    if (next < 0) break;
    let contentEnd = next;
    if (body.subarray(contentEnd-2, contentEnd).toString() === '\r\n') contentEnd -= 2;
    const disposition = headers.match(/content-disposition:\s*form-data;([^\r\n]+)/i)?.[1] || '';
    const name = disposition.match(/(?:^|;)\s*name="([^"]*)"/i)?.[1];
    const filename = disposition.match(/(?:^|;)\s*filename="([^"]*)"/i)?.[1];
    const contentType = headers.match(/content-type:\s*([^\r\n]+)/i)?.[1]?.trim() || 'application/octet-stream';
    if (name) parts.set(name, { filename: filename ? filename.split(/[\\/]/).pop() : '', contentType, data:body.subarray(headerEnd+4, contentEnd) });
    cursor = next;
  }
  return parts;
}
function cleanRecord(input) {
  const allowed = new Set(['title','description','notes','due','time','assignee','status','priority','visibility','date','attendees','meet_link','completed','body','progress','label']);
  return Object.fromEntries(Object.entries(input || {}).filter(([key]) => allowed.has(key)));
}
async function storage(path, method, data, contentType = 'application/octet-stream') {
  const { url, key } = config();
  const objectPath = path.split('/').map(encodeURIComponent).join('/');
  const headers = { apikey:key };
  if (!key.startsWith('sb_secret_')) headers.Authorization = `Bearer ${key}`;
  let endpoint = `${url}/storage/v1/object/gather-private/${objectPath}`;
  let body = data;
  if (method === 'GET') endpoint = `${url}/storage/v1/object/authenticated/gather-private/${objectPath}`;
  if (method === 'DELETE') { endpoint = `${url}/storage/v1/object/gather-private`; headers['Content-Type']='application/json'; body=JSON.stringify({prefixes:[path]}); }
  if (data) { headers['Content-Type'] = contentType; headers['x-upsert'] = 'true'; }
  const response = await fetch(endpoint, { method, headers, body });
  if (!response.ok) throw Object.assign(new Error('Private file storage is unavailable. Check the Supabase bucket setup.'), { status:502 });
  return method === 'GET' ? Buffer.from(await response.arrayBuffer()) : null;
}
async function ensureAdmin() {
  const email = (process.env.GATHER_ADMIN_EMAIL || 'ashutosh@lockin.com').trim().toLowerCase();
  const rows = await rest('team_users', `${eq('email', email)}&select=id`);
  if (rows?.length) return;
  const password = process.env.GATHER_ADMIN_PASSWORD;
  if (!password) throw Object.assign(new Error('Set GATHER_ADMIN_PASSWORD in Vercel before the first sign-in.'), { status:503 });
  const user = { id:`user-${crypto.randomUUID()}`, name:process.env.GATHER_ADMIN_NAME || 'Ashutosh', email, password_hash:passwordHash(password), role:'admin', active:true, avatar_path:'' };
  try { await rest('team_users', '', 'POST', user, 'return=minimal'); }
  catch (error) {
    const reread = await rest('team_users', `${eq('email', email)}&select=id`);
    if (!reread?.length) throw error;
  }
}
function sessionCookie(token, maxAge = SESSION_DAYS*86400) {
  return `gather_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function setCookie(res, value) { res.setHeader('Set-Cookie', value); }

async function run(req, res, route) {
  const method = (req.method || 'GET').toUpperCase();
  const url = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  const id = url.searchParams.get('id') || '';
  if (route !== '/health' && route !== '/login' && !validOrigin(req) && method !== 'GET') return send(res,403,{error:'Request origin was rejected.'});
  if (route === '/health' && method === 'GET') return send(res,200,{ok:true,configured:Boolean(process.env.SUPABASE_URL && (process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY))});
  try {
    config();
    if (route === '/login' && method === 'POST') {
      await ensureAdmin();
      const data = await jsonBody(req); const email=String(data.email||'').trim().toLowerCase(); const password=String(data.password||'');
      const users = await rest('team_users', `${eq('email',email)}&active=eq.true&select=*`);
      const user = users?.[0];
      if (!user || !passwordMatches(password,user.password_hash)) return send(res,401,{error:'Those sign-in details didn’t work. Check them and try again.'});
      const token=crypto.randomBytes(32).toString('base64url');
      const expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();
      await rest('sessions','','POST',{token_hash:tokenHash(token),user_id:user.id,expires_at:expires},'return=minimal');
      setCookie(res,sessionCookie(token)); return send(res,200,{user:publicUser(user)});
    }
    if (route === '/me' && method === 'GET') {
      const user=await currentUser(req); return send(res,200,{user:user?publicUser(user):null});
    }
    if (route === '/logout' && method === 'POST') {
      const token=cookieValue(req,'gather_session'); if(token) await rest('sessions',eq('token_hash',tokenHash(token)),'DELETE',undefined,'return=minimal');
      setCookie(res,sessionCookie('',0)); return send(res,200,{ok:true});
    }
    if (route === '/bootstrap' && method === 'GET') {
      const user=await requireUser(req,res); if(!user)return;
      const [team,records,files,settings]=await Promise.all([
        rest('team_users','active=eq.true&select=id,name,email,role,active,avatar_path&order=created_at.asc'),
        rest('records','select=id,kind,owner_id,data,created_at&order=created_at.desc'),
        rest('files','select=id,owner_id,filename,size,content_type,description,created_at&order=created_at.desc'),
        rest('settings','select=key,value'),
      ]);
      const grouped=Object.fromEntries([...KINDS].map(kind=>[kind,(records||[]).filter(row=>row.kind===kind).map(row=>({...row.data,id:row.id,owner_id:row.owner_id,created_at:row.created_at}))]));
      return send(res,200,{user:publicUser(user),team:(team||[]).map(publicUser),workspace:Object.fromEntries((settings||[]).map(s=>[s.key,s.value])),files:files||[],...grouped});
    }
    if (route === '/change-password' && method === 'POST') {
      const user=await requireUser(req,res); if(!user)return;
      const data=await jsonBody(req); if(!passwordMatches(String(data.old_password||''),user.password_hash))return send(res,400,{error:'Your current password does not match.'});
      const next=String(data.new_password||''); if(next.length<10)return send(res,400,{error:'Use at least 10 characters for your new password.'});
      await rest('team_users',eq('id',user.id),'PATCH',{password_hash:passwordHash(next)},'return=minimal');
      await rest('sessions',eq('user_id',user.id),'DELETE',undefined,'return=minimal'); setCookie(res,sessionCookie('',0)); return send(res,200,{ok:true});
    }
    if (route === '/invite' && method === 'POST') {
      const user=await requireUser(req,res); if(!user)return; if(user.role!=='admin')return send(res,403,{error:'Only admins can invite team members.'});
      const data=await jsonBody(req);const name=String(data.name||'').trim().slice(0,80),email=String(data.email||'').trim().toLowerCase(),password=String(data.password||'');
      if(!name||!/^\S+@\S+\.\S+$/.test(email))return send(res,400,{error:'Enter a name and valid email address.'});if(password.length<10)return send(res,400,{error:'Set a temporary password with at least 10 characters.'});
      await rest('team_users','','POST',{id:`user-${crypto.randomUUID()}`,name,email,password_hash:passwordHash(password),role:'member',active:true,avatar_path:''},'return=minimal');return send(res,201,{ok:true});
    }
    if (route === '/settings' && method === 'POST') {
      const user=await requireUser(req,res); if(!user)return; if(user.role!=='admin')return send(res,403,{error:'Only admins can manage workspace settings.'});
      const data=await jsonBody(req);const name=String(data.workspace_name||'').trim().slice(0,80);if(!name)return send(res,400,{error:'Workspace name can’t be empty.'});
      await rest('settings','on_conflict=key','POST',{key:'workspace_name',value:name},'resolution=merge-duplicates,return=minimal');return send(res,200,{workspace_name:name});
    }
    if (route === '/members' && method === 'PATCH') {
      const user=await requireUser(req,res);if(!user)return;if(user.role!=='admin')return send(res,403,{error:'Only admins can manage team access.'});
      const data=await jsonBody(req);const memberId=String(data.id||id);if(!memberId)return send(res,400,{error:'Choose a team member.'});if(memberId===user.id)return send(res,400,{error:'You can’t deactivate your own account.'});
      const members=await rest('team_users',`${eq('id',memberId)}&role=eq.member&select=id`);if(!members?.length)return send(res,404,{error:'That team member was not found.'});
      await rest('team_users',eq('id',memberId),'PATCH',{active:Boolean(data.active)},'return=minimal');if(!data.active)await rest('sessions',eq('user_id',memberId),'DELETE',undefined,'return=minimal');return send(res,200,{ok:true});
    }
    if (route === '/reset-password' && method === 'POST') {
      const user=await requireUser(req,res);if(!user)return;if(user.role!=='admin')return send(res,403,{error:'Only admins can reset team passwords.'});
      const data=await jsonBody(req);const memberId=String(data.id||'');const password=String(data.password||'');if(password.length<10)return send(res,400,{error:'Use at least 10 characters for the new password.'});
      const members=await rest('team_users',`${eq('id',memberId)}&role=eq.member&select=id`);if(!members?.length)return send(res,404,{error:'That team member was not found.'});
      await rest('team_users',eq('id',memberId),'PATCH',{password_hash:passwordHash(password)},'return=minimal');await rest('sessions',eq('user_id',memberId),'DELETE',undefined,'return=minimal');return send(res,200,{ok:true});
    }
    if (route === '/profile-photo' && method === 'POST') {
      const user=await requireUser(req,res);if(!user)return;const parts=await multipart(req,MAX_AVATAR+500000);const part=parts.get('photo');if(!part?.data?.length)return send(res,400,{error:'Choose a JPG, PNG, or WebP image.'});
      if(part.data.length>MAX_AVATAR)return send(res,413,{error:'Profile photos must be smaller than 5 MB.'});const ext=require('node:path').extname(part.filename).toLowerCase();if(IMAGE_TYPES.get(ext)!==part.contentType)return send(res,400,{error:'Choose a JPG, PNG, or WebP image.'});
      const stored=`${user.id}/avatar/${crypto.randomUUID()}${ext}`;await storage(stored,'POST',part.data,part.contentType);if(user.avatar_path)await storage(user.avatar_path,'DELETE');
      await rest('team_users',eq('id',user.id),'PATCH',{avatar_path:stored},'return=minimal');return send(res,200,{user:publicUser({...user,avatar_path:stored})});
    }
    if (route === '/avatar' && method === 'GET') {
      const user=await requireUser(req,res);if(!user)return;const targetId=id||url.searchParams.get('user_id')||user.id;const users=await rest('team_users',`${eq('id',targetId)}&active=eq.true&select=avatar_path`);if(!users?.[0]?.avatar_path)return send(res,404,{error:'Profile photo not found.'});
      const data=await storage(users[0].avatar_path,'GET');const ext=require('node:path').extname(users[0].avatar_path).toLowerCase();const mime=IMAGE_TYPES.get(ext)||'image/jpeg';return send(res,200,data,{'Content-Type':mime,'Cache-Control':'private, no-store'});
    }
    if (route === '/upload' && method === 'POST') {
      const user=await requireUser(req,res);if(!user)return;const parts=await multipart(req,MAX_FILE+1000000);const part=parts.get('file');if(!part?.filename||!part.data?.length)return send(res,400,{error:'Choose a file to upload.'});
      if(part.data.length>MAX_FILE)return send(res,413,{error:'Files must be smaller than 20 MB.'});const path=require('node:path');const ext=path.extname(part.filename).toLowerCase().slice(1);if(!FILE_TYPES.has(ext))return send(res,400,{error:'That file type is not supported.'});
      const stored=`${user.id}/files/${crypto.randomUUID()}.${ext}`;await storage(stored,'POST',part.data,part.contentType);const description=(parts.get('description')?.data||Buffer.alloc(0)).toString('utf8').slice(0,300);const created_at=new Date().toISOString();const id=`file-${crypto.randomUUID()}`;
      await rest('files','','POST',{id,owner_id:user.id,filename:part.filename.slice(0,180),stored_path:stored,size:part.data.length,content_type:part.contentType,description,created_at},'return=minimal');return send(res,201,{id,owner_id:user.id,filename:part.filename,size:part.data.length,content_type:part.contentType,description,created_at});
    }
    if (route === '/file-download' && method === 'GET') {
      const user=await requireUser(req,res);if(!user)return;const rows=await rest('files',`${eq('id',id)}&select=*`);const file=rows?.[0];if(!file)return send(res,404,{error:'File not found.'});
      const data=await storage(file.stored_path,'GET');const name=file.filename.replace(/["\r\n]/g,'_').slice(0,160);return send(res,200,data,{'Content-Type':file.content_type||'application/octet-stream','Content-Disposition':`attachment; filename="${name}"`,'Cache-Control':'private, no-store'});
    }
    if (KINDS.has(route.slice(1))) {
      const kind=route.slice(1);const user=await requireUser(req,res);if(!user)return;
      if(method==='POST'){
        const data=cleanRecord(await jsonBody(req));if(['tasks','reminders','meetings','goals'].includes(kind)&&!String(data.title||'').trim())return send(res,400,{error:'A title is required.'});if(kind==='meetings'&&data.meet_link&&!String(data.meet_link).startsWith('https://'))return send(res,400,{error:'Meeting links must use https.'});
        const item={id:`rec-${crypto.randomUUID()}`,kind,owner_id:user.id,data,created_at:new Date().toISOString()};await rest('records','','POST',item,'return=minimal');return send(res,201,{...data,id:item.id,owner_id:user.id,created_at:item.created_at});
      }
      if(method==='PATCH'||method==='DELETE'){
        const recordId=id||String((await jsonBody(req)).id||'');if(!recordId)return send(res,400,{error:'Choose an item.'});const rows=await rest('records',`${eq('id',recordId)}&${eq('kind',kind)}&select=*`);const item=rows?.[0];if(!item)return send(res,404,{error:'That item was not found.'});
        if(method==='DELETE'){
          if((kind==='updates'||kind==='files')&&item.owner_id!==user.id&&user.role!=='admin')return send(res,403,{error:'Only the person who added this item or an admin can remove it.'});
          await rest('records',`${eq('id',recordId)}&${eq('kind',kind)}`,'DELETE',undefined,'return=minimal');return send(res,200,{ok:true});
        }
        const change=cleanRecord(await jsonBody(req));if(kind==='meetings'&&change.meet_link&&!String(change.meet_link).startsWith('https://'))return send(res,400,{error:'Meeting links must use https.'});const next={...item.data,...change};await rest('records',`${eq('id',recordId)}&${eq('kind',kind)}`,'PATCH',{data:next},'return=minimal');return send(res,200,{...next,id:item.id,owner_id:item.owner_id,created_at:item.created_at});
      }
    }
    if(route==='/files'&&method==='DELETE'){
      const user=await requireUser(req,res);if(!user)return;const rows=await rest('files',`${eq('id',id)}&select=*`);const file=rows?.[0];if(!file)return send(res,404,{error:'That file was not found.'});if(file.owner_id!==user.id&&user.role!=='admin')return send(res,403,{error:'Only the person who added this item or an admin can remove it.'});
      await storage(file.stored_path,'DELETE');await rest('files',eq('id',id),'DELETE',undefined,'return=minimal');return send(res,200,{ok:true});
    }
    return send(res,404,{error:'API route not found.'});
  } catch (error) {
    const status=Number(error.status)||500;
    if(status>=500)console.error('Workspace API error:',error.message);
    return send(res,status,{error:error.message||'The workspace request failed.'});
  }
}

module.exports = { run };
