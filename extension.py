# -*- coding: utf-8 -*-
import re, subprocess, socket
from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("jumin & ip extension")
        callbacks.registerHttpListener(self)
        self._output = callbacks.getStdout()

        # 정규표현식 패턴 추가
        self.pattern1 = r'\b\d{2}(0[1-9]|1[0-2])\d{2}(0[1-9]|[12]\d|30|31)[1-4]\d{6}\b'     # 주민등록번호 패턴 1 (13자리)
        self.pattern2 = r'\b\d{2}(0[1-9]|1[0-2])\d{2}(0[1-9]|[12]\d|30|31)-[1-4]\d{6}\b' # 주민등록번호 패턴 2 (6자리-7자리)
        self.pattern3 = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' # 사설 ip 패턴 3

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            request_str = self._helpers.bytesToString(request)

            # 정규표현식으로 주민등록번호 패턴 검사
            matches = re.findall(self.pattern1, request_str) + re.findall(self.pattern2, request_str)

            if matches:
                # Request에 주민등록번호가 있는 경우 하이라이트 설정
                self.highlight_jumin_request(messageInfo)

                # 사이드 알림창에 메시지 표시
                self.show_jumin_notification("HTTP Request에 주민등록번호 또는 유사한 형식이 발견되었습니다")

        else:
            response = messageInfo.getResponse()
            response_str = self._helpers.bytesToString(response)

            # 정규표현식으로 주민등록번호 패턴 검사
            matches = re.findall(self.pattern1, response_str) + re.findall(self.pattern2, response_str)

            # 정규표현식으로 사설 ip 패턴 검사
            ip_matches = re.findall(self.pattern3, response_str)

            if matches:
                # Response에 주민등록번호가 있는 경우 하이라이트 설정
                self.highlight_jumin_response(messageInfo)

                # 사이드 알림창에 메시지 표시
                self.show_jumin_notification("HTTP Response에 주민등록번호 또는 유사한 형식이 발견되었습니다")
            
            if ip_matches:
                ip_address = ip_matches[0]
                is_private = self.is_private_ip(ip_address)

                if is_private:
                    # Response에 주민등록번호가 있는 경우 하이라이트 설정
                    self.highlight_ip_response(messageInfo)

                    # 사이드 알림창에 메시지 표시
                    self.show_ip_notification("HTTP Response에 사설 ip 형식이 발견되었습니다")

    def highlight_jumin_request(self, messageInfo):
        # 빨간색 하이라이트 설정
        messageInfo.setHighlight("red")

    def highlight_jumin_response(self, messageInfo):
        # 주황색 하이라이트 설정
        messageInfo.setHighlight("orange")
    
    def highlight_ip_response(self, messageInfo):
        # 파란색 하이라이트 설정
        messageInfo.setHighlight("blue")

    def show_jumin_notification(self, message):
        # macOS의 osascript를 사용하여 사이드 알림창 띄우기
        subprocess.Popen(['osascript', '-e', 'display notification "{}" with title "주민등록번호 발견"'.format(message)])

    def show_ip_notification(self, message):
        # macOS의 osascript를 사용하여 사이드 알림창 띄우기
        subprocess.Popen(['osascript', '-e', 'display notification "{}" with title "사설 ip 발견"'.format(message)])

    def is_private_ip(self, ip_address):
        try:
            # Validate the IP address using socket.inet_pton
            socket.inet_pton(socket.AF_INET, ip_address)
            # Convert the IP address to an integer and check if it's private
            ip_int = int(socket.inet_aton(ip_address).encode('hex'), 16)
            return ip_int >= 0x0A000000 and ip_int <= 0x0AFFFFFF or \
                   ip_int >= 0xAC100000 and ip_int <= 0xAC1FFFFF or \
                   ip_int >= 0xC0A80000 and ip_int <= 0xC0A8FFFF
        except socket.error:
            return False