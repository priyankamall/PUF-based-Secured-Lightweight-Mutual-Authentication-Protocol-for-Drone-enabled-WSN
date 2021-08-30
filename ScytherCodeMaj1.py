protocol Major1(SensorNode, Drone, CloudServer)
{
role SensorNode 
{
const IDs; 
fresh RMj,Rj,SKs-d: Nonce;
macro Aj = H(IDsj, IDd, Rj, RMj, Tj);
macro Bj = XOR( RMj, H(IDsj, Rj, Tj));
send_!1(SensorNode, Drone, IDsj, Aj, Bj, Tj); #Sensor node sends parameters to the relocatable base station (drones)
recv_!4(Drone, Sensor, IDd, Cd, Ed, Fd); #Drone receives parameters from the sensor node
macro Rd' = XOR(Fd, H(IDsj, LRj'));
macro SKs-d' = XOR(Ed, H(IDsj, RRj'));
macro Cd' = H(IDd, IDsj, Rd', SKs-d'); 
match(Cd', Cd); 
claim(SensorNode, Niagree); 
claim(SensorNode, Nisynch); 
claim(SensorNode,Secret, RMj);  
claim(SensorNode,Secret, Rj); 
claim(SensorNode,Secret, SKs-d); 
}
role Drone
{
const IDd;
fresh RMd,SKes-d: Nonce;
var RMj, Rj: Nonce;
recv_!1(SensorNode, Drone, IDsj, Aj, Bj, Tj);
macro L = H(IDd, Kd, RMd, Td);
macro N = XOR(RMd, H(IDcs, Kd));
send_!2(Drone, CloudServer, IDd, L, N, Td);
recv_!3(CloudServer, Drone, P, Q, V, Tcs); 
macro SKes-d' = XOR(V, H(IDd, Kd, Tcs));  
macro Rcs' = XOR(P, H(IDd, RMd));
macro Q' = H(IDd, IDcs, Rcs', SKes-d', Tcs);
match (Q,Q'); 
macro RMj' = XOR(Bj, H(IDsj, Rj', Tj)); 
macro Aj' = H(IDsj, IDd, Rj', RMj, Tj); 
match (Aj',Aj);
fresh Rd: Nonce;
fresh SKs-d: Nonce;
macro Cd = H(IDd, IDsj, Rd, SKs-d, LRj); 
macro Ed = XOR(SKs-d, H(IDsj, RRj));
macro Fd = XOR(Rd, H(IDsj, LRj));
send_!4(Drone, SensorNode, IDd, Cd, Ed, Fd); 
claim(SensorNode, Niagree);
claim (Drone, Nisynch);
claim(Drone,Secret, Rd);
claim(Drone,Secret, RMd); 
claim (Drone,Secret, SKs-d);
claim (Drone,Secret, SKes-d); 
}
role CloudServer
{
const Sc; 
recv_!2(Drone, CloudServer, IDd, L, N, Td ); 
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
send_!3(CloudServer, Drone, P,Q,V,Tcs); 
claim(CloudServer, Niagree); 
claim (CloudServer, Nisynch); 
claim(CloudServer,Secret, Rcs); 
claim_CloudServer(CloudServer,Secret, SKes-d); 
}
}
