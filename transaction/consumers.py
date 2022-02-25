# from cgitb import text
# import json
# from channels.generic.websocket import WebsocketConsumer

# class NotificationConsumer(WebsocketConsumer):
#     def connect(self):
#         self.accept()

#     def receive(self, text_data):
#         print(text_data)
#         self.send(text_data=json.dumps({'status': 'we got you'}))

#     def disconnect(self, *args, **kwargs):
#         print('disconnected')

#     def send_notification(self, event):
#         print('send notification')
#         data = json.loads(event.get('value'))
#         self.send(text_data=({'payload':event.get('value')}))

#         print('send notification')