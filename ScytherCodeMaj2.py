protocol Major2(User,Cloud) 
{ 
role User
{ 
fresh Rui,UCi: Nonce;
var URi,CRi: Nonce; 
var URi'':Nonce;
var RANcs,SKu-cs:Nonce; 
macro Updi = H(Pdi, Rui); 
send_!1(User,Cloud, IDi,Updi,UCi);
recv_!2(Cloud,User,URi,UAi,CRi); 
macro UDi= XOR(URi,Pdi);
macro UEi= XOR(CRi, H(IDi,Pdi));
macro UFi= XOR(Rui, H(XOR(IDi, Pdi,UCi))); 
macro UGi= H(IDi,Pdi,Rui); 
macro Rui'= XOR(UFi, H(XOR(IDi',Pdi',UCi))); 
macro UGi'= H(IDi', Pdi', Rui');
match(UGi', UGi);  
fresh RAN:Nonce;
macro URi'= XOR(Udi,Pdi'); 
macro Updi'= H(Pdi',Rui'); 
macro CRi'= XOR(UEi, H(IDi',Pdi'));
macro UKi= XOR(UAi,H(IDi',Updi',CRi')); 
macro ULi= H(IDi,UKi,CRi',RAN,Tui,URi'); 
macro UNi= XOR(RAN, H(IDcs,URi'));
send_!3(User,Cloud,IDi,UCi,ULi,UNi,Tui); 
recv_!4(Cloud,User, UQ,UP,UW,Tcs); 
macro SKu-cs''=XOR(UQ,H(IDi,URi,RAN)); 
macro RANcs''= XOR(UW,RAN);
macro RANcs'= {UP}SKu-cs''; 
claim(User, Niagree); 
claim(User, Nisynch); 
claim(User,Secret,Rui); 
claim(User,Secret,UCi); 
claim(User,Secret,RAN); 
claim(User,Secret,Pdi); 
claim(User,Secret,SKu-cs''); 
}

role Cloud 
{
const Sc,UCi,CRi; 
const IDcs; 
var Rui,UCi: Nonce; 
var RAN:Nonce; 
recv_!1(User, Cloud, IDi,Updi,UCi); 
fresh URi,CRi: Nonce; 
macro UAi= XOR(H(IDcs, SN, UCi), H(IDi,Updi,CRi)); 
send_!2(Cloud,User,URi,UAi,CRi); 
recv_!3(User,Cloud,IDi,UCi,ULi,UNi,Tui); 
fresh URi'':Nonce; 
macro RAN''= XOR(UNi, H(IDcs,URi''));
macro UKi''= H(IDcs, SN, UCi); 
macro ULi'= H(IDi'',UKi'',CRi, RAN'', Tui'', URi''); 
fresh RANcs,SKu-cs:Nonce; 
macro UQ= XOR(SKu-cs, H(IDi,URi,RAN''));
macro UP= {RANcs}SKu-cs; 
macro UW= XOR(RANcs,RAN''); 
send_!4(Cloud,User, UQ,UP,UW,Tcs); 
claim(Cloud,Niagree); 
claim(Cloud,Nisynch); 
claim(Cloud,Secret,RANcs);
claim(Cloud,Secret,SKu-cs); 
}
}
