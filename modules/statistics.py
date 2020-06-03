

class Statistics:
    def __init__(self):
        self.clients = {}
        self.recv_bytes = 0
        self.sent_bytes = 0

    def update(self, conn, recv_data, sent_data):
        self.recv_bytes += recv_data
        self.sent_bytes += sent_data
        ip = conn.ip
        host = conn.remote_host
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
        for conn_ip in self.clients:
            for host in self.clients[conn_ip]:
                data_info = self.clients[conn_ip][host]
                info = '{} - {}; Client received: {}, Client sent: {} \n'.format(
                    conn_ip, host, data_info[0], data_info[1])
                result += info

        return result
