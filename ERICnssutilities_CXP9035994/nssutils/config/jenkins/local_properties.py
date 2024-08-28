import os
import pkgutil


# POSSIBLE ENVIRON VALUES
# "production", "local", "testing", "jenkins"
ENVIRON = "jenkins"

LOCAL_DIR = os.path.join(pkgutil.get_loader('nssutils').filename, '..')  # Hardcoded for localhost and testing environments
REDIS_DB_INDEX = 2  # jenkins index as per http://confluence-nam.lmera.ericsson.se/display/TORRV/The+Team
