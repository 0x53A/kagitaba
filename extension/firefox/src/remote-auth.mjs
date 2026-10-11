/** Local-only remote credentials. The token is never part of a wallet or backup. */
export class RemoteAuth {
  constructor({store,crypto}) {this.store=store;this.crypto=crypto;this.record=null;this.session=null;}
  async load(){this.record=await this.store.get('remote-auth')??null;}
  public(url){const record=this.record?.url===url?this.record:null;return {username:record?.username??'',hasToken:!!record?.envelope,hasSessionToken:!!this.session&&this.session.url===url,remember:record?.remember??false,autoSync:record?.autoSync??false};}
  clearSession(){if(this.session)this.session.password='';this.session=null;}
  context(url,username){return JSON.stringify(['Kagitaba/browser/remote-auth/v1',url,username]);}
  async save(url,{username='',password='',remember=true,autoSync=false},identity,guard=()=>{}){
    if(typeof username!=='string'||username.length>256||typeof password!=='string'||password.length>16384||url.length>2048)throw Error('Invalid remote credentials');
    const old=this.record?.url===url?this.record:null;
    let transient=password||(this.session?.url===url&&this.session.username===username?this.session.password:'');
    let envelope;
    if(remember){
      if(transient){if(!identity)throw Error('Unlock the wallet to remember the remote token');const result=await this.crypto('local_encrypt',{identity,context:this.context(url,username),plaintext:transient});guard();envelope=result.envelope;}
      else if(old?.username===username)envelope=old.envelope;
    }else if(!transient&&identity&&old?.envelope&&old.username===username){
      const result=await this.crypto('local_decrypt',{identity,context:this.context(url,username),envelope:old.envelope});guard();transient=result.plaintext;
    }
    const next={version:1,url,username,remember:!!remember,autoSync:!!autoSync,...(envelope?{envelope}:{})};
    guard();await this.store.set('remote-auth',next);this.record=next;guard();this.clearSession();if(!remember&&transient)this.session={url,username,password:transient};
    return this.public(url);
  }
  async resolve(url,explicit,identity,guard=()=>{}){
    if(explicit?.password){return {username:explicit.username??'',password:explicit.password};}
    const record=this.record?.url===url?this.record:null;
    if(this.session&&this.session.url===url){
      if(!identity)throw Error('Unlock the wallet to use the saved remote token');
      if(explicit?.username&&explicit.username!==this.session.username)throw Error('Saved token belongs to a different remote username');
      return {username:this.session.username,password:this.session.password};
    }
    if(record?.envelope){
      if(!identity)throw Error('Unlock the wallet to use the saved remote token');
      if(explicit?.username && explicit.username!==record.username)throw Error('Saved token belongs to a different remote username');
      const result=await this.crypto('local_decrypt',{identity,context:this.context(url,record.username),envelope:record.envelope});guard();
      return {username:record.username,password:result.plaintext};
    }
    if(record?.username)throw Error('No saved remote token. Enter a token in connection settings');
    return {username:explicit?.username??'',password:''};
  }
}
