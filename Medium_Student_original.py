# Open the file in read mode
import  gzip
import platform
import sys
import math


if platform.system() == 'Windows':
    largeName = 'Hide_and_seek_PC.csv.gz'
    smallname = 'HideSmall.csv.mac.gz'
else:
    smallname = 'HideSmall.csv.mac.gz'
    largeName = 'Hide_and_seek.csv.gz'


#this_is_header = True
#headerItems =  [ ]
fileInfo = [ ]

list_of_ports = dict()

smallname = 'HideSmall.csv.gz'
largeName = 'Hide_and_seek.csv.gz'

filename = smallname

def count_stddev_for_orig_pkts(lines):
    """
    Calculates the standard deviation for the 'orig_pkts' column for both 'Benign' and 'Malicious' traffic labels.

    This function processes a list of lines, where each line represents a data entry with multiple columns.
    It extracts the 'orig_pkts' (index 17) and computes the standard deviation of the values for entries labeled
    as "Benign" and "Malicious" in the 'Traffic_Labeled' column (index 23).

    Args:
        lines (list): A list of lists where each sublist represents a line of data with multiple columns.

    Returns:
        tuple: A tuple containing two float values:
            - The standard deviation of 'orig_pkts' for "Benign" traffic.
            - The standard deviation of 'orig_pkts' for "Malicious" traffic.

    Raises:
        AssertionError: If any of the following conditions occur:
            - The lines list is empty or None.
            - 'orig_pkts' or 'traffic_label' is empty or invalid.
            - There are no valid entries for "Benign" or "Malicious" traffic.
    """
    assert lines is not None
    assert len(lines) > 1

    benign_values = []
    malicious_values = []

    line_index = 1

    for line in lines:
        orig_pkts = line[17].strip()  # Column for 'orig_pkts' (index 17)
        assert orig_pkts is not None, "Empty orig_pkts? Should be impossible, check data"
        traffic_Label = line[23].strip()  # Column for 'Traffic_Labeled' (index 23)
        assert traffic_Label is not None, "Empty label? Should be impossible, check data"
        assert isinstance(traffic_Label, str)

        try:
            orig_pkts_val = int(orig_pkts)  # Convert 'orig_pkts' to an integer

            if "Benign" in traffic_Label:
                benign_values.append(orig_pkts_val)
            else:
                malicious_values.append(orig_pkts_val)

            line_index += 1

        except ValueError:
            print(f"Bad number on line {line_index}")

    # Function to calculate standard deviation
    def calculate_stddev(values):
        if len(values) == 0:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    # Calculate the standard deviation for Benign
    stddev_ben = calculate_stddev(benign_values)

    # Calculate the standard deviation for Malicious
    stddev_mal = calculate_stddev(malicious_values)

    return stddev_ben, stddev_mal

def  count_average_for_id_orig_p( lines ):
    assert lines is not None
    assert len(lines) > 1

    total_mal = 0
    count_mal = 0

    total_ben = 0
    count_ben = 0

    line_index = 1

    for line in lines:
        id_orig_p = line[4].strip()
        assert id_orig_p is not None, "Emprt id_orig_p? Should be impossible check data"
        traffic_Label  =  line[23].strip()
        assert traffic_Label is not None, "Empty lable  ?  Should be impossible check data"
        assert isinstance( traffic_Label , str )
        try:
            idorig_p_val = int(id_orig_p )
            if  "Benign" in traffic_Label :
                total_ben += idorig_p_val
                count_ben += 1
            else:
                total_mal += idorig_p_val
                count_mal += 1

            line_index += 1

        except:
            print("fBad nummber on line {line_index} ")
    #end for
    averge_ben = 0
    if count_ben == 0:
        assert False , "Zero count of Benign, should be impossible  "
    else:
        averge_ben = total_ben/ count_ben

    averge_mal = 0
    if count_mal == 0 :
        assert False , "Zero count of Malware should be impossible"
    else:
        averge_mal = total_mal/count_mal

    return averge_ben, averge_mal

def read_file_as_list_of_strings_DO_NOT_PROFILE(  filename :str )-> list[ list[ str ]]:
    """
    converts each line into a list of strings
    then each line is added to a list.

    :param filename:
    :return:

    """
    result = [ ]
    this_is_header = True
    headerItems =  [  ]

    with gzip.open(filename, 'rt') as file:

        # Iterate over each line in the file
        for line in file:
            # Strip leading/trailing whitespace and split the line into an array of strings
            words = line.strip().split(',')  # You can replace split() with split(',') or other delimiters if needed
            if this_is_header:
                headerItems = words
                this_is_header = False
            else:
                # print(words)  # Print or process the array of strings\=
                result.append(words)

                #end if
        #end for
    #end with
    assert len(result )> 1
    return result

#------------------------------------------------------------------------------
def find_unique_sourceIP_addresses(lines):
    assert lines is not None
    assert len(lines) > 1
    source_IP_address = [ ]
    ip_to_list_of_ports = [ ]

    for words in lines:
        id_resp_h = words[6].strip()
        id_orig_p = words[4].strip()
        # print(  id_resp_h,id_orig_p  )
        if id_resp_h in source_IP_address:
            index = -101
            try:
                index =  source_IP_address.index( id_resp_h )
            except ValueError:
                assert False ,"Should never happen - we checked already "
            except:
                assert  False, "What else could go wrong ? "
            assert index != -101

            list = ip_to_list_of_ports[index  ]

            if id_orig_p not in list:
                list.append(id_orig_p)  # append for list
                ip_to_list_of_ports[ index  ] = list
        else: #id_resp_h NO in list_of_ports
            #print( f"Makeing 2",id_resp_h , id_orig_p  )
            lst =  [ id_orig_p   ]
            assert len( lst )== 1
            source_IP_address.append(  id_resp_h )
            assert source_IP_address[ -1 ] == id_resp_h, "Not at end "
            ip_to_list_of_ports.append( lst )
            assert ip_to_list_of_ports[  -1 ] == lst

    print("Final len ", len(source_IP_address))

    return   source_IP_address , ip_to_list_of_ports

#------------------------------------------------------------------------------
def save_process_all_lines_values_DO_NOT_PROFILE( name,  source_IP_address , ip_to_list_of_ports  ):
    with open( name , 'w') as file:
        for line in  range( len( source_IP_address)  ) :
            file.write(  source_IP_address[ line]  + '->' )
            for port in ip_to_list_of_ports[ line ]:
                file.write(port + ',')
            file.write('\n')
#------------------------------------------------------------------------------
def test_process_all_lines_values( source_IP_address , ip_to_list_of_ports  ):
    sum = 0

    for index in  range( len(source_IP_address)  ) :
        val = int( source_IP_address[ index ] )
        sum += val
        assert isinstance(  ip_to_list_of_ports[ index  ] , list )
        for k in ip_to_list_of_ports[ index  ]:
            v = int( k )
            sum += v
    return val
#------------------------------------------------------------------------------
def  count_unique_ids_compute( lines ):
    unique = list()
    duplicates = list()
    for words in lines:
        uid = words[2].strip()
        if uid in unique:
            duplicates.insert(0, uid )
        else:
            unique.insert( 0 , uid)

    return len(unique), len(duplicates)
#------------------------------------------------------------------------------
def count_unique_ids( lines ):
    assert lines is not None
    assert len(lines) > 1
    unique,duplicates  =  count_unique_ids_compute(lines)
    assert unique  > 0 , "should be impossible"
    return unique,duplicates
#------------------------------------------------------------------------------
def check_correct_output_DO_NOT_PROFILE( filename ,  source_IP_address , ip_to_list_of_ports  ):
    sum = test_process_all_lines_values(source_IP_address, ip_to_list_of_ports)
    print("final sum ", sum)

    if filename == smallname:
        if sum != 15990:
            print("WARNING - you are not produceing the outptu from process_all_lines_values correclty ")

#------------------------------------------------------------------------------
def check_correct_unique_DO_NOT_PROFILE(filename, unquieIDs, duplicates):
    if duplicates != 0:
        sys.stderr.write(f"WARNING  {duplicates} is the wrong value the computation is wrong \n")

    if filename == largeName:
        if unquieIDs != 938550:
            sys.stderr.write(f"WARNING  {unquieIDs} is the wrong value the computation is wrong \n")
    return

    if filename == smallname:
        if unquieIDs != 1999:
            sys.stderr.write(f"WARNING  {unquieIDs} is the wrong value the computation is wrong \n")
    return

    sys.stderr.write(f"I don't know {filename}\n")
#------------------------------------------------------------------------------
def count_average_for_orig_pkts(lines):
    assert lines is not None
    assert len(lines) > 1

    total_ben = 0
    count_ben = 0

    total_mal = 0
    count_mal = 0

    line_index = 1

    for line in lines:
        orig_pkts = line[17].strip()  # Column for 'orig_pkts' (index 17)
        assert orig_pkts is not None, "Empty orig_pkts? Should be impossible, check data"
        traffic_Label = line[23].strip()  # Column for 'Traffic_Labeled' (index 23)
        assert traffic_Label is not None, "Empty label? Should be impossible, check data"
        assert isinstance(traffic_Label, str)

        try:
            orig_pkts_val = int(orig_pkts)  # Convert 'orig_pkts' to an integer

            if "Benign" in traffic_Label:
                total_ben += orig_pkts_val
                count_ben += 1
            else:
                total_mal += orig_pkts_val
                count_mal += 1

            line_index += 1

        except ValueError:
            print(f"Bad number on line {line_index}")

    # Calculate average orig_pkts for Benign
    average_ben = 0
    if count_ben == 0:
        assert False, "Zero count of Benign, should be impossible"
    else:
        average_ben = total_ben / count_ben

    # Calculate average orig_pkts for Malicious
    average_mal = 0
    if count_mal == 0:
        assert False, "Zero count of Malware should be impossible"
    else:
        average_mal = total_mal / count_mal

    return average_ben, average_mal
#------------------------------------------------------------------------------
def count_average_for_orig_ip_bytes(lines):
    """
     Calculates the average number of 'orig_ip_bytes' for both 'Benign' and 'Malicious' traffic labels.

     This function processes a list of lines, where each line represents a data entry with multiple columns.
     It extracts the 'orig_ip_bytes' (index 18) and calculates the averages for entries labeled as "Benign"
     and "Malicious" in the 'Traffic_Labeled' column (index 23). It ensures that the data is valid and properly
     categorized, and raises assertion errors if there are issues with the input data.

     Args:
         lines (list): A list of lists where each sublist represents a line of data with multiple columns.

     Returns:
         tuple: A tuple containing two float values:
             - The average 'orig_ip_bytes' for "Benign" traffic.
             - The average 'orig_ip_bytes' for "Malicious" traffic.

     Raises:
         AssertionError: If any of the following conditions occur:
             - The lines list is empty or None.
             - 'orig_ip_bytes' or 'traffic_label' is empty or invalid.
             - There are no valid entries for "Benign" or "Malicious" traffic.
     """


    assert lines is not None
    assert len(lines) > 1

    total_ben = 0
    count_ben = 0

    total_mal = 0
    count_mal = 0

    line_index = 1

    for line in lines:
        orig_ip_bytes = line[18].strip()  # Column for 'orig_ip_bytes' (index 18)
        assert orig_ip_bytes is not None, "Empty orig_ip_bytes? Should be impossible, check data"
        traffic_Label = line[23].strip()  # Column for 'Traffic_Labeled' (index 23)
        assert traffic_Label is not None, "Empty label? Should be impossible, check data"
        assert isinstance(traffic_Label, str)

        try:
            orig_ip_bytes_val = int(orig_ip_bytes)  # Convert 'orig_ip_bytes' to an integer

            if "Benign" in traffic_Label:
                total_ben += orig_ip_bytes_val
                count_ben += 1
            else:
                total_mal += orig_ip_bytes_val
                count_mal += 1

            line_index += 1

        except ValueError:
            print(f"Bad number on line {line_index}")

    # Calculate average orig_ip_bytes for Benign
    average_ben = 0
    if count_ben == 0:
        assert False, "Zero count of Benign, should be impossible"
    else:
        average_ben = total_ben / count_ben

    # Calculate average orig_ip_bytes for Malicious
    average_mal = 0
    if count_mal == 0:
        assert False, "Zero count of Malware should be impossible"
    else:
        average_mal = total_mal / count_mal

    return average_ben, average_mal
#------------------------------------------------------------------------------
def count_average_for_duration(lines):
    """
    Calculates the average duration (in hundredths of a second) for both 'Benign' and 'Malicious' traffic labels.

    This function processes a list of lines, where each line represents a data entry with multiple columns.
    It extracts the 'duration' (index 9) and converts the value into 100ths of a second before calculating
    the averages for entries labeled as "Benign" and "Malicious" in the 'Traffic_Labeled' column (index 23).
    It ensures that the data is valid and properly categorized, and raises assertion errors if there are issues
    with the input data.

    Args:
        lines (list): A list of lists where each sublist represents a line of data with multiple columns.

    Returns:
        tuple: A tuple containing two float values:
            - The average duration (in hundredths of a second) for "Benign" traffic.
            - The average duration (in hundredths of a second) for "Malicious" traffic.

    Raises:
        AssertionError: If any of the following conditions occur:
            - The lines list is empty or None.
            - 'duration' or 'traffic_label' is empty or invalid.
            - There are no valid entries for "Benign" or "Malicious" traffic.
    """
    assert lines is not None
    assert len(lines) > 1

    total_ben = 0
    count_ben = 0

    total_mal = 0
    count_mal = 0

    line_index = 1

    for line in lines:
        duration = line[9].strip()  # Column for 'duration' (index 9)
        assert duration is not None, "Empty duration? Should be impossible, check data"
        traffic_Label = line[23].strip()  # Column for 'Traffic_Labeled' (index 23)
        assert traffic_Label is not None, "Empty label? Should be impossible, check data"
        assert isinstance(traffic_Label, str)

        if len( duration )< 4 :
            continue

        try:
            # Convert duration from string to seconds in hundredths of a second (if in the format '0 days HH:MM:SS.ssssss')
            if 'days' in duration:  # For duration in the format like '0 days 00:00:02.998796'
                time_str = duration.split('days')[1].strip()  # Extract HH:MM:SS.ssssss part
            else:
                time_str = duration.strip()  # Duration already in HH:MM:SS.ssssss format

            # Parse the time into hours, minutes, seconds, and microseconds
            h, m, s = time_str.split(':')
            sec, microsec = s.split('.')
            total_seconds = int(h) * 3600 + int(m) * 60 + int(sec) + int(microsec) / 1000000

            # Convert to hundredths of a second
            duration_in_hundredths = total_seconds * 100

            if "Benign" in traffic_Label:
                total_ben += duration_in_hundredths
                count_ben += 1
            else:
                total_mal += duration_in_hundredths
                count_mal += 1

            line_index += 1

        except ValueError:
            print(f"Bad number on line {line_index}")

    # Calculate average duration in hundredths of a second for Benign
    average_ben = 0
    if count_ben == 0:
        assert False, "Zero count of Benign, should be impossible"
    else:
        average_ben = total_ben / count_ben

    # Calculate average duration in hundredths of a second for Malicious
    average_mal = 0
    if count_mal == 0:
        assert False, "Zero count of Malware should be impossible"
    else:
        average_mal = total_mal / count_mal

    return average_ben, average_mal



def main( lines ):
    """ This is where all the calcuations happen."""
    average_ben, average_mal = count_average_for_id_orig_p(lines)
    print(f" Average id_orig_p benign = {average_ben:.2f}, average id_orig_p malware = {average_mal:.2f}")

    average_ben_pkts, average_mal_pkts = count_average_for_orig_pkts(lines)
    print(f" Average pkts benign = {average_ben_pkts:.2f}, average pkts malware = {average_mal_pkts:.2f}")
    stdev_ben_pkts, stdev_mal_pkts = count_stddev_for_orig_pkts(lines)
    print(f" std dev pkts benign = {stdev_ben_pkts:.2f}, std dev  pkts malware = {stdev_mal_pkts:.2f}")

    average_OIB_ben, average_OIB_mal = count_average_for_orig_ip_bytes(lines)
    print(f" Average OIB benign = {average_OIB_ben:.2f}, average OIB malware = {average_OIB_mal:.2f}")

    average_duration_ben, average_duration_mal = count_average_for_duration(lines)
    print(
        f" Average duration benign = {average_duration_ben:.2f}, average duration malware = {average_duration_mal:.2f}")

    print(" count_unique_ids ")
    unquieIDs, duplicates = count_unique_ids(lines)
    print("Unique ID ", unquieIDs, " lines ", len(lines))

    print("Compute  VERSION ")
    source_IP_address, ip_to_list_of_ports = find_unique_sourceIP_addresses(lines)

    return unquieIDs, duplicates, source_IP_address , ip_to_list_of_ports



if __name__ == "__main__":
    #don't profile this
    lines = read_file_as_list_of_strings_DO_NOT_PROFILE( filename ) # smallname

    #  process this in profiler
    unquieIDs, duplicates, source_IP_address, ip_to_list_of_ports = main(lines)
    # don't profile this
    save_process_all_lines_values_DO_NOT_PROFILE( filename + "Processes.csv", source_IP_address , ip_to_list_of_ports )
    check_correct_output_DO_NOT_PROFILE( filename ,  source_IP_address , ip_to_list_of_ports  )
    check_correct_unique_DO_NOT_PROFILE( filename ,  unquieIDs, duplicates )



