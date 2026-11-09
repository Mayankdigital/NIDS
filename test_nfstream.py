import nfstream
streamer = nfstream.NFStreamer(source='/home/mayank/Desktop/DATACOLLECTION/nids_dataset/captures/benign/BENIGN_001.pcap')
df = streamer.to_pandas()
print(df.shape)
