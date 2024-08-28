#! /bin/bash

# method of analysis :
# 1 - convert pcap file to text file (temporary text file)
# 2 - read the text file line by line , every line as string
# 3 - get 3 parameter from every string : source - destination - protocol
# 4 - create 2 arrays for every parameter parameter_types  types_counter
# 5 - the index number for every type is the same at counter array
#     ex : ("http" "udp" "dns") (5 10 7) -> http:5 / udp:10 / dns:7
# 6 - abstract text file from functions and deal only with arrays
# 7 - looping in counter array (binary search) to get highest counter
# 8 - index of highest counters_array is the same of types_array
# 9 - creating new text file same_name_of_pcap_file_sts
# 10 - printing the highest counted type of array 
# 11 - unset the printed element every loop to get the lower value next loop 

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

# function to check if an element exists in destination array 
check_dest() 
{
    check_dest_sts=0  # this variable will be checked later in another function
    input_dest=$des   # $des -> is the name of the element to be checked
   
   cd=0  # counter of the array
    for item in "${dest[@]}"; do
    test "$input_dest" = "$item" && check_dest_sts=1 && index_d=$cd 
    (( cd++ ))
    done
    # if the element exists the sts will be 1 and its index will be saved in index_d
}
# same like check_dest
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
# same like check_dest
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
   str=$IN  #$IN -> will include every single line in the temporary text file
IFS=' ' read -r -a ARR <<< "$str" # the string will be saved as array in ARR
sour=${ARR[2]} # source is in element 2 in the array
des=${ARR[4]} # destination is in element 4 in the array
pro=${ARR[5]} # protocol is in element 5 in the array



  check_protocols #check element exists or not
if [ $check_protocols_sts = 1 ]; then
  (( c_protocols[$index_p]++ )) # if exist -> increment its index in counter array
else
 protocols+=($pro) # if not exist -> add it to the protocols array
 c_protocols+=(1)  # if not exist -> add 1 to counter array 
 (( protocols_size++ ))
fi
  # this way both types and its counter will be in the same index
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
 # function to get maximum counter index  
pro_max_index()
{
  max=${c_protocols[0]}
for n in "${c_protocols[@]}" ; do
    ((n > max)) && max=$n # max : will include the value of maximum counter
done

value=$max
  for i in "${!c_protocols[@]}"; do # search foe thw index of maximum value
   if [[ "${c_protocols[$i]}" = "${value}" ]]; then
       c_pro=$i; # the index will be saved in c_pro
   fi
done

}

print_protocols()
{
  
  for each in "${protocols[@]}"
do
  pro_max_index # search for the index every loop
  echo "${protocols[$c_pro]} : ${c_protocols[$c_pro]}" >> $new # print information in new file
  unset c_protocols[$c_pro] # unset the maximum to get a new maximum value next loop
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
  
  for each in {1..5} # print only top five as requested in requirements
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
  
  for each in {1..5} # print only top five as requested in requirements
do
  dest_max_index
  echo "${dest[$c_des]} : ${c_dest[$c_des]}" >> $new
  unset c_dest[$c_des]
  
done
  
}
################ Application start

echo -n "What is the name of your PCAP input file? "
read in_pcap #get the pcap file name from user

tshark -r ~/shark_files/${in_pcap}  > ~/shark_files/temp.txt #change path due to your machine
new=~/shark_files/${in_pcap}_sts #change path due to your machine
touch $new
# tshark -r -> to abstarct data from pcap file to textfile in temp.txt
# create new file in same directory and same_name_sts 
echo "----- Network Traffic Analysis Report -----" > $new
echo "" >> $new
num_of_packets=0
while IFS= read -r line; do # read temp.txt line by line
(( num_of_packets++ )) # counter of number of packets
 IN=$line
analyze_line # get destination - source - protocol from every single line
 
done < ~/shark_files/temp.txt

echo "1. Total Packets: $num_of_packets " >> $new
echo "" >> $new

pro_max_index 
echo "2. Protocols: " >> $new
print_protocols
echo "" >> $new
echo "3. Top 5 Source IP Addresses:" >> $new
print_sources
echo "" >> $new
echo "4. Top 5 Destination IP Addresses:" >> $new
print_dest
echo "" >> $new
echo "----- End of Report -----" >> $new
