protocol Major2(User,CloudServer) 
{ 
role User
{ 
fresh Rui,UCi: Nonce;
var URi,CRi: Nonce; 
var URi'':Nonce;
var RANcs,SKu-cs:Nonce; 
macro Updi = H(Pdi, Rui); 
send_!1(User,CloudServer, IDi,Updi,UCi);#User sends parameters to the cloud server
recv_!2(CloudServer,User,URi,UAi,CRi); #Cloud server receives parameters from the user
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
send_!3(User,CloudServer,IDi,UCi,ULi,UNi,Tui); #User sends parameters to the cloud server
recv_!4(CloudServer,User, UQ,UP,UW,Tcs); #Cloud server receives parameters from the user
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

role CloudServer 
{
const Sc,UCi,CRi; 
const IDcs; 
var Rui,UCi: Nonce; 
var RAN:Nonce; 
recv_!1(User, CloudServer, IDi,Updi,UCi); 
fresh URi,CRi: Nonce; 
macro UAi= XOR(H(IDcs, SN, UCi), H(IDi,Updi,CRi)); 
send_!2(CloudServer,User,URi,UAi,CRi); 
recv_!3(User,CloudServer,IDi,UCi,ULi,UNi,Tui); 
fresh URi'':Nonce; 
macro RAN''= XOR(UNi, H(IDcs,URi''));
macro UKi''= H(IDcs, SN, UCi); 
macro ULi'= H(IDi'',UKi'',CRi, RAN'', Tui'', URi''); 
fresh RANcs,SKu-cs:Nonce; 
macro UQ= XOR(SKu-cs, H(IDi,URi,RAN''));
macro UP= {RANcs}SKu-cs; 
macro UW= XOR(RANcs,RAN''); 
send_!4(CloudServer,User, UQ,UP,UW,Tcs); 
claim(CloudServer,Niagree); 
claim(CloudServer,Nisynch); 
claim(CloudServer,Secret,RANcs);
claim(CloudServer,Secret,SKu-cs); 
}
}
