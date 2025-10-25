// document.addEventListener('DOMContentLoaded',()=>{
  
//   const form=document.getElementById('loginForm');
//   const msg=document.getElementById('msg');

//   form.addEventListener('submit',async (e)=>{
//     e.preventDefault();
//     msg.textContent='';
//     const username=document.getElementById('username').value.trim();
//     const password=document.getElementById('password').value;

//     if(!username||!password){ msg.textContent='Please enter username and password.'; return }

//     try{
//       // Read CSRF token from cookie (double-submit). If not present, server will reject.
//       const getCookie = (name) => document.cookie.split('; ').find(row => row.startsWith(name + '='))?.split('=')[1];
//       const csrf = getCookie('csrf_token') || '';
//       const res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token': decodeURIComponent(csrf)},body:JSON.stringify({username,password})});
//       const data=await res.json();
//       if(res.ok&&data.success){
//         msg.style.color='lightgreen';
//         msg.textContent='Login successful — redirecting...';
//         // placeholder: redirect to dashboard (not implemented)
//         setTimeout(()=>{ window.location.href='/home'; },800);
//       } else {
//         msg.style.color='#ffdede';
//         msg.textContent=data.message||'Login failed.';
//       }
//     }catch(err){
//       msg.style.color='#ffdede';
//       msg.textContent='Network or server error.';
//       console.error(err);
//     }
//   });
// });


  document.getElementById('loginForm').addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent default form submission

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            // Simple client-side validation (replace with server-side for security)
            if (username === 'admin' && password === 'Cyb3rGang') {
                window.location.href = '../Threat-Protection-HIDS/code/index.html'; // Redirect to dashboard
            } else {
                alert('Invalid username or password.');
            }
        });