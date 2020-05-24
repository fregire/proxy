

class Statistics:
    def __init__(self):
        self.clients = {}

    def update(self, client, recv_data, sent_data):
        ip = client.ip
        host = client.remote_host
        if ip not in self.clients:
            self.clients.update({ip: {host: (recv_data, sent_data)}})
        elif host not in self.clients[ip]:
            self.clients[ip].update({host: (recv_data, sent_data)})
        else:
            data_info = self.clients[ip][host]
            prev_recv_data = data_info[0]
            prev_sent_data = data_info[1]
            new_data_info = (prev_recv_data + recv_data,
                             prev_sent_data + sent_data)
            self.clients[ip][host] = new_data_info

    def get_formatted_stats(self):
        result = ''
        for client_ip in self.clients:
            for host in self.clients[client_ip]:
                data_info = self.clients[client_ip][host]
                info = '{} - {}; Client received: {}, Client sent: {} \n'.format(
                    client_ip, host, data_info[0], data_info[1])
                result += info

        return result
