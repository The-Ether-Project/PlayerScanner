import sqlite3
from mcstatus import MinecraftServer
con = sqlite3.connect('videlicet.db')
cur = con.cursor()
res = cur.execute('SELECT DISTINCT IP, PORT FROM BASIC_PINGS WHERE PLAYERS_ONLINE > 0 AND TIMESTAMP > 1636264319257')

blacklist = ["00000000-0000-0000-0000-000000000000"]


for x in res:
    print(x)
    '''
    server = MinecraftServer(x[0],x[1])
    try:
        status = server.status()
    except:
        pass
    else:
        if status.players.sample is not None:
            for player in status.players.sample:
                if player.id not in blacklist:
                    print("{} ({})".format(player.name, player.id) )
    '''


