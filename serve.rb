require 'webrick'
server = WEBrick::HTTPServer.new(
  Port: 7788,
  DocumentRoot: '/Users/cgx/Desktop/cgx_nas/Agent/Skill-Detection',
  BindAddress: '127.0.0.1',
  Logger: WEBrick::Log.new('/dev/null'),
  AccessLog: []
)
trap('INT') { server.stop }
server.start
