#! /bin/bash

# just analyze string and capture : source - dest - protocol

#####    arrays

protocols=(" ")
c_protocols=(" ")
source=(" ")
c_source=(" ")
dest=(" ")
c_dest=(" ")

protocols_size=0
source_size=0
dest_size=0

#input_protocol
#check_protocols_sts
check_dest()
{
    check_dest_sts=0
    input_dest=$des
   
   cd=0
    for item in "${dest[@]}"; do
    test "$input_dest" = "$item" && check_dest_sts=1 && index_d=$cd 
    (( cd++ ))
    done
}

check_source()
{
    check_source_sts=0
    input_source=$sour
   
   cc=0
    for item in "${source[@]}"; do
    test "$input_source" = "$item" && check_source_sts=1 && index_s=$cc 
    (( cc++ ))
    done
}

check_protocols()
{
    check_protocols_sts=0
    input_protocol=$pro
   
   c=0
    for item in "${protocols[@]}"; do
    test "$input_protocol" = "$item" && check_protocols_sts=1 && index_p=$c  
    (( c++ ))
    done
}


analyze_line()
{
   str=$IN 
IFS=' ' read -r -a ARR <<< "$str"
sour=${ARR[2]}
des=${ARR[4]}
pro=${ARR[5]}



  check_protocols
if [ $check_protocols_sts = 1 ]; then
  (( c_protocols[$index_p]++ ))
else
 protocols+=($pro)
 c_protocols+=(1) 
 (( protocols_size++ ))
fi
  
  check_source
  if [ $check_source_sts = 1 ]; then
  (( c_source[$index_s]++ ))
else
 source+=($sour)
 c_source+=(1) 
 (( source_size++ ))
fi
 
  check_dest
    if [ $check_dest_sts = 1 ]; then
  (( c_dest[$index_d]++ ))
else
 dest+=($des)
 c_dest+=(1) 
 (( dest_size++ ))
fi
}
  
pro_max_index()
{
  max=${c_protocols[0]}
for n in "${c_protocols[@]}" ; do
    ((n > max)) && max=$n
done

value=$max
  for i in "${!c_protocols[@]}"; do
   if [[ "${c_protocols[$i]}" = "${value}" ]]; then
       c_pro=$i;
   fi
done

}

print_protocols()
{
  for each in "${protocols[@]}"
do
  pro_max_index
  echo "${protocols[$c_pro]} : ${c_protocols[$c_pro]}" >> $new
  unset c_protocols[$c_pro]
done
  
}

 #################

source_max_index()
{
  mx=${c_source[0]}
for n in "${c_source[@]}" ; do
    ((n > mx)) && mx=$n
done

val=$mx
  for i in "${!c_source[@]}"; do
   if [[ "${c_source[$i]}" = "${val}" ]]; then
       c_sor=$i;
   fi
done

}

print_sources()
{
  for each in "${source[@]}"
do
  source_max_index
  echo "${source[$c_sor]} : ${c_source[$c_sor]}" >> $new
  unset c_source[$c_sor]
done
  
}
############# dest
dest_max_index()
{
  mx=${c_dest[0]}
for n in "${c_dest[@]}" ; do
    ((n > mx)) && mx=$n
done

val=$mx
  for i in "${!c_dest[@]}"; do
   if [[ "${c_dest[$i]}" = "${val}" ]]; then
       c_des=$i;
   fi
done

}

print_dest()
{
  for each in "${dest[@]}"
do
  dest_max_index
  echo "${dest[$c_des]} : ${c_dest[$c_des]}" >> $new
  unset c_dest[$c_des]
done
  
}
################
echo -n "What is the name of your PCAP input file? "
read in_pcap

tshark -r ~/shark_files/${in_pcap}  > ~/shark_files/temp.txt
new=~/shark_files/${in_pcap}_sts
touch $new

echo "----- Network Traffic Analysis Report -----" > $new
num_of_packets=0
while IFS= read -r line; do
(( num_of_packets++ ))
 IN=$line
analyze_line
 
done < ~/shark_files/temp.txt

echo "1. Total Packets: $num_of_packets " >> $new
#IN=" 73  16.844840 108.159.102.116 → 192.168.1.7  TCP 66 [TCP ACKed unseen segment] 443 → 40610 [ACK] Seq=1 Ack=2 Win=145 Len=0 TSval=1830934516 TSecr=4225895418"
#analyze_line
#IN=" 113  21.926556 LiteonTe_4c:70:15 → HuaweiTe_cc:7d:07 ARP 42 Who has 192.168.1.1? Tell 192.168.1.7"
#analyze_line
#IN=" 1   0.000000 216.58.211.202 → 192.168.1.7  UDP 1292 443 → 39129 Len=1250"
#analyze_line
#IN=" 73  16.844840 108.159.102.116 → 192.168.1.7  TCP 66 [TCP ACKed unseen segment] 443 → 40610 [ACK] Seq=1 Ack=2 Win=145 Len=0 TSval=1830934516 TSecr=4225895418"
#analyze_line
#IN=" 113  21.926556 LiteonTe_4c:70:15 → HuaweiTe_cc:7d:07 ARP 42 Who has 192.168.1.1? Tell 192.168.1.7"
#analyze_line
#IN=" 1   0.000000 216.58.211.202 → 192.168.1.7  UDP 1292 443 → 39129 Len=1250"
#analyze_line
#IN=" 1   0.000000 216.58.211.202 → 192.168.1.7  UDP 1292 443 → 39129 Len=1250"
#analyze_line


#echo "${protocols[@]}"
#echo "${c_protocols[@]}"
#echo "${source[@]}"
#echo "${c_source[@]}"
#echo "${dest[@]}"
#echo "${c_dest[@]}"
#echo "$num_of_packets"
#echo "$protocols_size"
#echo "$source_size"
#echo "$dest_size"
#echo "${c_dest[2]}"
#pro_max_index
echo "2. Protocols: " >> $new
print_protocols
echo "3. Top 5 Source IP Addresses:" >> $new
print_sources
echo "4. Top 5 Destination IP Addresses:" >> $new
print_dest
echo "----- End of Report -----" >> $new
#print_protocols
#print_protocols
#print_protocols
#print_protocols
