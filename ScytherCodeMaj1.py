protocol Major1(Sensor, Drone, Cloud)
{
role Sensor 
{
const IDs; 
fresh RMj,Rj,SKs-d: Nonce;
macro Aj = H(IDsj, IDd, Rj, RMj, Tj);
macro Bj = XOR( RMj, H(IDsj, Rj, Tj));
send_!1(Sensor, Drone, IDsj, Aj, Bj, Tj); 
recv_!4(Drone, Sensor, IDd, Cd, Ed, Fd); 
macro Rd' = XOR(Fd, H(IDsj, LRj'));
macro SKs-d' = XOR(Ed, H(IDsj, RRj'));
macro Cd' = H(IDd, IDsj, Rd', SKs-d'); 
match(Cd', Cd); 
claim(Sensor, Niagree); 
claim(Sensor, Nisynch); 
claim(Sensor,Secret, RMj);  
claim(Sensor,Secret, Rj); 
claim(Sensor,Secret, SKs-d); 
}
role Drone
{
const IDd;
fresh RMd,SKes-d: Nonce;
var RMj, Rj: Nonce;
recv_!1(Sensor, Drone, IDsj, Aj, Bj, Tj);
macro L = H(IDd, Kd, RMd, Td);
macro N = XOR(RMd, H(IDcs, Kd));
send_!2(Drone, Cloud, IDd, L, N, Td);
recv_!3(Cloud, Drone, P, Q, V, Tcs); 
macro SKes-d' = XOR(V, H(IDd, Kd, Tcs));  
macro Rcs' = XOR(P, H(IDd, RMd));
macro Q' = H(IDd, IDcs, Rcs', SKes-d', Tcs);
match (Q,Q'); 
macro RMj' = XOR(Bj, H(IDsj, Rj', Tj)); 
macro Aj' =H(IDsj, IDd, Rj', RMj, Tj); 
match (Aj',Aj);
fresh Rd: Nonce;
fresh SKs-d: Nonce;
macro Cd = H(IDd, IDsj, Rd, SKs-d, LRj); 
macro Ed = XOR(SKs-d, H(IDsj, RRj));
macro Fd = XOR(Rd, H(IDsj, LRj));
send_!4(Drone, Sensor, IDd, Cd, Ed, Fd); 
claim(Sensor, Niagree);
claim (Drone, Nisynch);
claim(Drone,Secret, Rd);
claim(Drone,Secret, RMd); 
claim (Drone,Secret, SKs-d);
claim (Drone,Secret, SKes-d); 
}
role Cloud
{
const Sc; 
recv_!2(Drone, Cloud, IDd, L, N, Td ); 
const IDcs; 
fresh Rcs: Nonce; 
fresh SKes-d: Nonce;
macro kd' = H(IDd, IDcs, SN, T); 
macro RMd' = XOR(N, H(IDcs, Kd')); 
macro L' = H(IDd, Kd', RMd', Td);
match (L', L);
macro P = XOR(Rcs, H(IDd, RMd')); 
macro V = XOR(SKes-d, H(IDd, Kd', Tcs));
macro Q = H(IDd, IDcs, Rcs, SKes-d, Tcs); 
send_!3(Cloud, Drone, P,Q,V,Tcs); 
claim(Cloud, Niagree); 
claim (Cloud, Nisynch); 
claim(Cloud,Secret, Rcs); 
claim_Cloud(Cloud,Secret, SKes-d); 
}
}