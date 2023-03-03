from core.PyNet import PyNet, PyNet_template, PyNet_session

template = PyNet_template()
server = PyNet(address='0.0.0.0')
server.session_manager = PyNet_session('sUp3R_S3CuR3_kE1!1!')

@server.add_endpoint('/upload', ['GET', 'POST'])
def uplaod(request, response):
    if request.verb == 'POST':
        #print(request.file['file']['content'])
        #print(request.post['testerino'])
        #print(request.get)
        response.set_cookie('lang', 'en_US')
        #print(request.request_headers)
        print(request.file['file']['filename'])
        #pass
    return template.template('upload.html')

@server.add_endpoint('/', ['GET', 'POST'])
def peppa(request, response):
    if not request.session.get('username'):
        response.session['username'] = 'Mimmo'
        username = response.session['username']
    else:
        username = request.session['username']
    if not request.cookie.get('lang'):
        response.set_cookie('lang', 'en_US')
    #response.session['test'] = 'HEHE'
    #request.post['test']
    #username = request.session.get('usernamme') #__import__('os').popen('whoami').read()
    return template.template('index.html', username=username)


def main():
    server.serve()


if __name__ == '__main__':
    main()