import pathlib
import time
def create_file(size):
    local_time = time.strftime("%Y-%m-%d",time.localtime())
    file_name = str(pathlib.Path(__file__).parent) + "/data/" + str(local_time) + '.txt'
    big_file = open(file_name,'w')
    big_file.seek(1024*1024*1024* int(size))
    big_file.write('test')
    big_file.close()

if __name__ == '__main__':
    n = input('G\r\n')
    create_file(n)
