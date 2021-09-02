usertype Timestamp, PUF, SK;#SK is the secret key
hashfunction H;
const IDd, IDs, IDcs, SN, T, Kd, Aj, Bj, Tj, IDsj, Cj, 
L,N, Td, Tcs, Kd', RMd', RMd, L', P, U, Q, Q', SKes-d',
RMj', Rj', Cd, Ed, Fd, LRj,LRj', RRj,RRj', Rd', SKs-d', Cd',V ;
const ADD:Function;
protocol Major1(SensorNode, Drone, CloudServer)
{
role SensorNode 
{
const IDs; #sensor node identity
fresh RMj,Rj,SKs-d: Nonce;#randomly chosen values
macro Aj = H(IDsj, IDd, Rj, RMj, Tj);
macro Bj = XOR( RMj, H(IDsj, Rj, Tj));
send_!1(SensorNode, Drone, IDsj, Aj, Bj, Tj); #Sensor node sends parameters to the relocatable base station (drones)
recv_!4(Drone, Sensor, IDd, Cd, Ed, Fd); #Drone receives parameters from the sensor node
macro Rd' = XOR(Fd, H(IDsj, LRj'));
macro SKs-d' = XOR(Ed, H(IDsj, RRj'));
macro Cd' = H(IDd, IDsj, Rd', SKs-d'); 
match(Cd', Cd); 
claim(SensorNode, Niagree); #non-injective agreement
claim(SensorNode, Nisynch); #Non-injective synchronization
claim(SensorNode,Secret, RMj);  
claim(SensorNode,Secret, Rj); 
claim(SensorNode,Secret, SKs-d); #sensor node and drone's common key secrecy
}
role Drone
{
const IDd;#identity of drone
fresh RMd,SKes-d: Nonce;
var RMj, Rj: Nonce;
recv_!1(SensorNode, Drone, IDsj, Aj, Bj, Tj); #sensor node receives parameters from the drone
macro L = H(IDd, Kd, RMd, Td);
macro N = XOR(RMd, H(IDcs, Kd));
send_!2(Drone, CloudServer, IDd, L, N, Td);#Drone sends parameters to the cloud server
recv_!3(CloudServer, Drone, P, Q, V, Tcs); #Cloud server receives parameters from the drone
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
send_!4(Drone, SensorNode, IDd, Cd, Ed, Fd); #Drone sends parameters to the sensor node
claim(SensorNode, Niagree); #non-injective agreement
claim (Drone, Nisynch);#Non-injective synchronization
claim(Drone,Secret, Rd);
claim(Drone,Secret, RMd); 
claim (Drone,Secret, SKs-d);#Checks whether the common key SKs-d is secret
claim (Drone,Secret, SKes-d); # Checks whether the common key SKes-d is secret
}
role CloudServer
{
const Sc; 
recv_!2(Drone, CloudServer, IDd, L, N, Td ); #drone receives parameters from the cloud server
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
send_!3(CloudServer, Drone, P,Q,V,Tcs); #cloud server sends parameters to the drone
claim(CloudServer, Niagree); #non-injective agreement 
claim (CloudServer, Nisynch); #Non-injective synchronization
claim(CloudServer,Secret, Rcs); 
claim_CloudServer(CloudServer,Secret, SKes-d); 
}
}
