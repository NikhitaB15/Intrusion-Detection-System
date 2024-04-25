import pandas as pd
import numpy as np
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler, LabelEncoder
import streamlit as st
from sklearn.naive_bayes import BernoulliNB
loaded_model = pickle.load(open('trained_model.sav', 'rb'))
st.write('Intrusion Detection')
def main():
    input1=st.text_input('Duration')
    duration= int(input1)
    protocol_type = st.selectbox('Protocol type', ['tcp', 'udp','icmp'])
    service= st.text_input('Service')
    flag= st.text_input('Flag')
    src_bytes= int(st.text_input('Source bytes'))
    dst_bytes = int(st.text_input('Destination bytes'))
    land= int(st.text_input('Land'))
    wrong_fragment = int(st.text_input('Wrong fragment'))
    urgent= int(st.text_input('urgent'))
    hot = int(st.text_input('Hot'))
    num_failed_logins= int(st.text_input('Number of failed logins'))
    logged_in= int(st.text_input('Logged in'))
    num_compromised = int(st.text_input('Number of compromised accounts'))
    root_shell= int(st.text_input('root_shell'))
    su_attempted = int(st.text_input('su_attempted'))
    num_root= int(st.text_input('Number of root accesses'))
    num_file_creations = int(st.text_input('Number of file creations'))
    num_shells= int(st.text_input('Number of shell accesses'))
    num_access_files= int(st.text_input('Number of access files'))
    num_outbound_cmds=int(st.text_input('number of outbound commands'))
    is_host_login= int(st.text_input('Is host login'))
    is_guest_login = int(st.text_input('Is guest login'))
    count = int(st.text_input('Count'))
    srv_count = int(st.text_input('SRV count'))
    serror_rate = float(st.text_input('Serror rate'))
    srv_serror_rate = float(st.text_input('SRV serrror rate'))
    rerror_rate = float(st.text_input('Rerror rate'))
    srv_rerror_rate = float(st.text_input('SRV rerror rate'))
    same_srv_rate = float(st.text_input('Same SRV rate'))
    diff_srv_rate= float(st.text_input('Diff SRV rate'))
    srv_diff_host_rate = float(st.text_input('SRV diff host rate'))
    dst_host_count = int(st.text_input('Destination host count'))
    dst_host_srv_count= int(st.text_input('Destination host SRV count'))
    dst_host_same_srv_rate = float(st.text_input('Destination host same SRV rate'))
    dst_host_diff_srv_rate = float(st.text_input('Destination host diff SRV rate'))
    dst_host_same_src_port_rate= float(st.text_input('Destination host same src port rate'))
    dst_host_srv_diff_host_rate = float(st.text_input('Destination host SRV diff host rate'))
    dst_host_serror_rate= float(st.text_input('Destination host serrror rate'))
    dst_host_srv_serror_rate= float(st.text_input('Destination host SRV serrror rate'))
    dst_host_rerror_rate= float(st.text_input('Destination host rerror rate'))


    if st.button('Result'):
        # Your input collection and preprocessing remain the same

        le_service = LabelEncoder()
        le_service.fit(['ftp_data', 'other', 'private', 'http', 'remote_job', 'name',
                    'netbios_ns', 'eco_i', 'mtp', 'telnet', 'finger', 'domain_u',
                    'supdup', 'uucp_path', 'Z39_50', 'smtp', 'csnet_ns', 'uucp',
                    'netbios_dgm', 'urp_i', 'auth', 'domain', 'ftp', 'bgp', 'ldap',
                    'ecr_i', 'gopher', 'vmnet', 'systat', 'http_443', 'efs', 'whois',
                    'imap4', 'iso_tsap', 'echo', 'klogin', 'link', 'sunrpc', 'login',
                    'kshell', 'sql_net', 'time', 'hostnames', 'exec', 'ntp_u',
                    'discard', 'nntp', 'courier', 'ctf', 'ssh', 'daytime', 'shell',
                    'netstat', 'pop_3', 'nnsp', 'IRC', 'pop_2', 'printer', 'tim_i',
                    'pm_dump', 'red_i', 'netbios_ssn', 'rje', 'X11', 'urh_i',
                    'http_8001'])
        service = le_service.transform([service])[0]
        le_flag = LabelEncoder()
        le_flag.fit(['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3', 'S2', 'OTH'])
        flag = le_flag.transform([flag])[0]

        protocol_type_mapping = {
            "tcp": 1,
            "udp": 2,
            "icmp": 3
        }
        protocol_type = protocol_type_mapping[protocol_type]

        input_data = [
            duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment,
            urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted,
            num_root, num_file_creations, num_shells, num_access_files,num_outbound_cmds, is_host_login, is_guest_login,
            count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
            diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
            dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
            dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate

        ]
        # changing the input_data to numpy array
        input_data_as_numpy_array = np.asarray(input_data)

        # reshape the array as we are predicting for one instance
        input_data_reshaped = input_data_as_numpy_array.reshape(1, -1)


        # make a prediction using the Random Forest Classifier
        LR_prediction = loaded_model.predict(input_data_reshaped)

        # print the prediction
        st.write(LR_prediction)
        st.write('The class is ', LR_prediction[0])

if __name__ == '__main__':
    main()
