const https=require('https'),fs=require('fs');const [host,port,ca,cert,key]=process.argv.slice(2);
const o={host,port,path:'/',ca:fs.readFileSync(ca),checkServerIdentity:()=>undefined,timeout:5000};
try{ if(cert){o.cert=fs.readFileSync(cert);o.key=fs.readFileSync(key)} }catch(e){console.log('FAIL load',e.code||'',e.message.slice(0,120));process.exit(0)}
https.get(o,r=>{console.log('OK HTTP',r.statusCode,'node',process.version,'openssl',process.versions.openssl);r.resume()}).on('error',e=>console.log('FAIL',e.code||'',String(e.message).slice(0,140),'node',process.version,'openssl',process.versions.openssl));
