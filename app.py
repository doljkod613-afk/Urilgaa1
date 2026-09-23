import os, sqlite3, secrets, hashlib, hmac
from flask import Flask, request, jsonify, session, send_from_directory, abort
try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'urilgaa.db')
DATABASE_URL = os.environ.get('DATABASE_URL')
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

def db():
    if DATABASE_URL and psycopg:
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def qmark(sql):
    return sql.replace('?', '%s') if DATABASE_URL and psycopg else sql

def init_db():
    c = db()
    if DATABASE_URL and psycopg:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS invitations(
            id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), title TEXT NOT NULL,
            type TEXT, slug TEXT UNIQUE, date TEXT, time TEXT, venue TEXT, message TEXT,
            template TEXT DEFAULT 'classic')""")
        c.execute("""CREATE TABLE IF NOT EXISTS guests(
            id SERIAL PRIMARY KEY, invitation_id INTEGER REFERENCES invitations(id) ON DELETE CASCADE,
            name TEXT NOT NULL, phone TEXT, status TEXT DEFAULT 'pending')""")
    else:
        c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,pw TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS invitations(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT NOT NULL,type TEXT,slug TEXT UNIQUE,date TEXT,time TEXT,venue TEXT,message TEXT,template TEXT DEFAULT 'classic');
        CREATE TABLE IF NOT EXISTS guests(id INTEGER PRIMARY KEY,invitation_id INTEGER,name TEXT NOT NULL,phone TEXT,status TEXT DEFAULT 'pending');""")
    c.commit(); c.close()

def hp(p):
    s = secrets.token_bytes(16); k = hashlib.pbkdf2_hmac('sha256', p.encode(), s, 120000)
    return s.hex() + ':' + k.hex()

def cp(p, x):
    try:
        s, k = x.split(':')
        t = hashlib.pbkdf2_hmac('sha256', p.encode(), bytes.fromhex(s), 120000).hex()
        return hmac.compare_digest(t, k)
    except Exception:
        return False

def user():
    if not session.get('uid'): return None
    c = db(); x = c.execute(qmark('SELECT id,name,email FROM users WHERE id=?'), (session['uid'],)).fetchone(); c.close()
    return x

def need():
    if not user(): return jsonify(error='Нэвтэрнэ үү'), 401

def insert_and_id(c, sql, params):
    if DATABASE_URL and psycopg:
        row = c.execute(sql + ' RETURNING id', params).fetchone()
        return row['id']
    cur = c.execute(sql, params); return cur.lastrowid

@app.get('/')
def home(): return send_from_directory(app.static_folder, 'index.html')

@app.post('/api/register')
def reg():
    d=request.json or {}; n=d.get('name','').strip(); e=d.get('email','').strip().lower(); p=d.get('password','')
    if not n or not e or len(p)<6: return jsonify(error='Нэр, email, 6+ тэмдэгттэй нууц үг шаардлагатай.'),400
    c=db()
    try:
        uid=insert_and_id(c,qmark('INSERT INTO users(name,email,pw) VALUES(?,?,?)'),(n,e,hp(p))); c.commit(); session['uid']=uid; return jsonify(ok=True)
    except Exception as ex:
        c.rollback(); return jsonify(error='Энэ email бүртгэлтэй байж магадгүй.'),409
    finally: c.close()

@app.post('/api/login')
def login():
    d=request.json or {}; c=db(); x=c.execute(qmark('SELECT * FROM users WHERE email=?'),(d.get('email','').lower(),)).fetchone(); c.close()
    if not x or not cp(d.get('password',''),x['pw']): return jsonify(error='Email эсвэл нууц үг буруу.'),401
    session['uid']=x['id']; return jsonify(ok=True)

@app.post('/api/logout')
def logout(): session.clear(); return jsonify(ok=True)
@app.get('/api/me')
def me():
    u=user(); return jsonify(user=dict(u) if u else None)

@app.get('/api/invitations')
def invs():
    if (e:=need()): return e
    c=db(); rows=c.execute(qmark("""SELECT i.*,COUNT(g.id) guests,
    SUM(CASE WHEN g.status='yes' THEN 1 ELSE 0 END) yes_count,
    SUM(CASE WHEN g.status='maybe' THEN 1 ELSE 0 END) maybe_count,
    SUM(CASE WHEN g.status='no' THEN 1 ELSE 0 END) no_count
    FROM invitations i LEFT JOIN guests g ON g.invitation_id=i.id
    WHERE i.user_id=? GROUP BY i.id ORDER BY i.id DESC"""),(user()['id'],)).fetchall(); c.close()
    return jsonify([dict(x) for x in rows])

@app.post('/api/invitations')
def create():
    if (e:=need()): return e
    d=request.json or {}; slug=(d.get('slug') or secrets.token_urlsafe(6)).lower().replace(' ','-'); c=db()
    while c.execute(qmark('SELECT 1 FROM invitations WHERE slug=?'),(slug,)).fetchone(): slug += '-' + secrets.token_hex(2)
    iid=insert_and_id(c,qmark('INSERT INTO invitations(user_id,title,type,slug,date,time,venue,message,template) VALUES(?,?,?,?,?,?,?,?,?)'),
      (user()['id'],d.get('title','Миний урилга'),d.get('type','birthday'),slug,d.get('date',''),d.get('time',''),d.get('venue',''),d.get('message',''),d.get('template','classic')))
    c.commit(); c.close(); return jsonify(id=iid,slug=slug)

@app.put('/api/invitations/<int:iid>')
def edit(iid):
    if (e:=need()): return e
    d=request.json or {}; c=db(); x=c.execute(qmark('SELECT * FROM invitations WHERE id=? AND user_id=?'),(iid,user()['id'])).fetchone()
    if not x: c.close(); return jsonify(error='Олдсонгүй'),404
    c.execute(qmark('UPDATE invitations SET title=?,type=?,date=?,time=?,venue=?,message=?,template=? WHERE id=?'),
      (d.get('title',x['title']),d.get('type',x['type']),d.get('date',x['date']),d.get('time',x['time']),d.get('venue',x['venue']),d.get('message',x['message']),d.get('template',x['template']),iid)); c.commit(); c.close(); return jsonify(ok=True)

@app.delete('/api/invitations/<int:iid>')
def delete(iid):
    if (e:=need()): return e
    c=db(); c.execute(qmark('DELETE FROM guests WHERE invitation_id IN (SELECT id FROM invitations WHERE id=? AND user_id=?)'),(iid,user()['id'])); c.execute(qmark('DELETE FROM invitations WHERE id=? AND user_id=?'),(iid,user()['id'])); c.commit(); c.close(); return jsonify(ok=True)

@app.get('/api/invitations/<int:iid>/guests')
def guests(iid):
    if (e:=need()): return e
    c=db(); x=c.execute(qmark('SELECT 1 FROM invitations WHERE id=? AND user_id=?'),(iid,user()['id'])).fetchone()
    if not x: c.close(); return jsonify(error='Олдсонгүй'),404
    r=c.execute(qmark('SELECT * FROM guests WHERE invitation_id=? ORDER BY id DESC'),(iid,)).fetchall(); c.close(); return jsonify([dict(x) for x in r])

@app.post('/api/invitations/<int:iid>/guests')
def addg(iid):
    if (e:=need()): return e
    d=request.json or {}; c=db(); x=c.execute(qmark('SELECT 1 FROM invitations WHERE id=? AND user_id=?'),(iid,user()['id'])).fetchone()
    if not x: c.close(); return jsonify(error='Олдсонгүй'),404
    gid=insert_and_id(c,qmark('INSERT INTO guests(invitation_id,name,phone) VALUES(?,?,?)'),(iid,d.get('name','Зочин'),d.get('phone',''))); c.commit(); c.close(); return jsonify(id=gid)

@app.put('/api/guests/<int:gid>')
def editg(gid):
    if (e:=need()): return e
    d=request.json or {}; c=db(); x=c.execute(qmark('SELECT g.* FROM guests g JOIN invitations i ON i.id=g.invitation_id WHERE g.id=? AND i.user_id=?'),(gid,user()['id'])).fetchone()
    if not x: c.close(); return jsonify(error='Олдсонгүй'),404
    c.execute(qmark('UPDATE guests SET name=?,phone=?,status=? WHERE id=?'),(d.get('name',x['name']),d.get('phone',x['phone']),d.get('status',x['status']),gid)); c.commit(); c.close(); return jsonify(ok=True)

@app.delete('/api/guests/<int:gid>')
def delg(gid):
    if (e:=need()): return e
    c=db(); c.execute(qmark('DELETE FROM guests WHERE id=? AND invitation_id IN (SELECT id FROM invitations WHERE user_id=?)'),(gid,user()['id'])); c.commit(); c.close(); return jsonify(ok=True)

@app.get('/i/<slug>')
def public(slug):
    c=db(); x=c.execute(qmark('SELECT id FROM invitations WHERE slug=?'),(slug,)).fetchone(); c.close()
    if not x: abort(404)
    return send_from_directory(app.static_folder,'public.html')

@app.get('/api/public/<slug>')
def pdata(slug):
    c=db(); x=c.execute(qmark('SELECT * FROM invitations WHERE slug=?'),(slug,)).fetchone(); c.close(); return jsonify(dict(x)) if x else (jsonify(error='Урилга олдсонгүй'),404)

@app.post('/api/public/<slug>/rsvp')
def rsvp(slug):
    d=request.json or {}; c=db(); x=c.execute(qmark('SELECT id FROM invitations WHERE slug=?'),(slug,)).fetchone()
    if not x: c.close(); return jsonify(error='Урилга олдсонгүй'),404
    n=d.get('name','').strip(); s=d.get('status','')
    if not n or s not in ('yes','maybe','no'): c.close(); return jsonify(error='Нэр болон RSVP сонголт шаардлагатай.'),400
    g=c.execute(qmark('SELECT id FROM guests WHERE invitation_id=? AND lower(name)=lower(?)'),(x['id'],n)).fetchone()
    if g: c.execute(qmark('UPDATE guests SET status=? WHERE id=?'),(s,g['id']))
    else: insert_and_id(c,qmark('INSERT INTO guests(invitation_id,name,status) VALUES(?,?,?)'),(x['id'],n,s))
    c.commit(); c.close(); return jsonify(ok=True)

if __name__=='__main__':
    init_db(); app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=True)
