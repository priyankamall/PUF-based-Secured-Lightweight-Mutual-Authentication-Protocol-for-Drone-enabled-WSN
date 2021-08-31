protocol Major2(User,CloudServer) 
{ 
role User
{ 
fresh Rui,UCi: Nonce;#UCi Challenges
var URi,CRi: Nonce; #CRi random number
var URi'':Nonce;
var RANcs,SKu-cs:Nonce; 
macro Updi = H(Pdi, Rui); 
send_!1(User,CloudServer, IDi,Updi,UCi);#User sends parameters to the cloud server
                                        #via open channel
recv_!2(CloudServer,User,URi,UAi,CRi); #Cloud server receives parameters from the user
                                        #via offline / encrypted link
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
                                                #via open channel
recv_!4(CloudServer,User, UQ,UP,UW,Tcs); #Cloud server receives parameters from the user
macro SKu-cs''=XOR(UQ,H(IDi,URi,RAN)); #session key between user and cloud server
macro RANcs''= XOR(UW,RAN);
macro RANcs'= {UP}SKu-cs''; #decryption
claim(User, Niagree); #check non-injective agreement
claim(User, Nisynch); #check non-injective synchronization
claim(User,Secret,Rui); 
claim(User,Secret,UCi); 
claim(User,Secret,RAN);#verify the random number secrecy 
claim(User,Secret,Pdi); 
claim(User,Secret,SKu-cs''); #session key secrecy verification
}

role CloudServer 
{
const Sc,UCi,CRi; 
const IDcs; 
var Rui,UCi: Nonce; 
var RAN:Nonce; 
recv_!1(User, CloudServer, IDi,Updi,UCi); #User receives parameters from the cloud server
fresh URi,CRi: Nonce; 
macro UAi= XOR(H(IDcs, SN, UCi), H(IDi,Updi,CRi)); 
send_!2(CloudServer,User,URi,UAi,CRi); #Cloud server sends parameters to the user
recv_!3(User,CloudServer,IDi,UCi,ULi,UNi,Tui); #User receives parameters from the cloud server
fresh URi'':Nonce; 
macro RAN''= XOR(UNi, H(IDcs,URi''));
macro UKi''= H(IDcs, SN, UCi); 
macro ULi'= H(IDi'',UKi'',CRi, RAN'', Tui'', URi''); 
fresh RANcs,SKu-cs:Nonce; 
macro UQ= XOR(SKu-cs, H(IDi,URi,RAN''));
macro UP= {RANcs}SKu-cs; #encyption process of the session key
macro UW= XOR(RANcs,RAN''); 
send_!4(CloudServer,User, UQ,UP,UW,Tcs); #Cloud server sends parameters to the user
claim(CloudServer,Niagree); #check non-injective agreement
claim(CloudServer,Nisynch); #check non-injective synchronization
claim(CloudServer,Secret,RANcs);#random number secrecy
claim(CloudServer,Secret,SKu-cs); #session key secrecy
}
}
