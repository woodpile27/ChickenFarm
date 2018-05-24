import ConfigParser

cfg = ConfigParser.ConfigParser()
cfg.read('chickenfarm.cfg')

REDIS_HOST = cfg.get("farm","redis_host")
REDIS_PORT = cfg.get("farm","redis_port")
MONGO_URI = cfg.get("farm","mongo_uri")
MONGO_DB = cfg.get("farm","mongo_db")
MONGO_TABLE1 = cfg.get("farm","mongo_table1")
MONGO_TABLE2 = cfg.get("farm","mongo_table2")
KEYWORD = cfg.get("farm","file_keyword")
IMAGE_NAME = cfg.get("wetland","image_name")
