from text2vec import Similarity
from text2vec import Word2Vec
from text2vec import SentenceModel, EncoderType
from text2vec.utils.distance import cosine_distance
from datetime import datetime


# 中文句向量模型(CoSENT)，中文语义匹配任务推荐，支持fine-tune继续训练
#t2v_model = SentenceModel("shibing624/text2vec-base-chinese",
#                          encoder_type=EncoderType.FIRST_LAST_AVG, device='cpu')
# 支持多语言的句向量模型（Sentence-BERT），英文语义匹配任务推荐，支持fine-tune继续训练
#sbert_model = SentenceModel("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
#                            encoder_type = EncoderType.MEAN, device='cpu')

sbert_model = SentenceModel("sentence-transformers/all-MiniLM-L6-v2",
                            encoder_type = EncoderType.MEAN, device='cpu')


# 中文词向量模型(word2vec)，中文字面匹配任务和冷启动适用
#w2v_model = Word2Vec("w2v-light-tencent-chinese")

def compute_emb(model,sentences):
    sentence_embeddings = model.encode(sentences)
    return sentence_embeddings

    """
    print(type(sentence_embeddings), sentence_embeddings.shape)
    # The result is a list of sentence embeddings as numpy arrays
    for sentence, embedding in zip(sentences, sentence_embeddings):
        print("Sentence:", sentence)
        print("Embedding shape:", embedding.shape)
        print("Embedding head:", embedding[:10])
    """

def compute_similarity_score(emb1, emb2):
    score = float(cosine_distance(emb1, emb2))
    return score

sim_model = Similarity()
def similarity(sentence1:str,sentence2:str):
    score = sim_model.get_score(sentence1, sentence2)
    return score

def test():
    # Two lists of sentences
    sentences1 = ['如何更换花呗绑定银行卡',
                  'The cat sits outside',
                  'A man is playing guitar',
                  'The new movie is awesome']

    sentences2 = ['花呗更改绑定银行卡',
                  'The dog plays in the garden',
                  'A woman watches TV',
                  'The new movie is so great']
    model = sbert_model
    for i in range(len(sentences1)):
        for j in range(len(sentences2)):
          s0 = datetime.now()
          emb1 = compute_emb(model,sentences1[i])
          s1 = datetime.now()
          emb2 = compute_emb(model,sentences2[j])
          s2 = datetime.now()
          score = compute_similarity_score(emb1,emb2)
          s3 = datetime.now()
          score2 = similarity(sentences1[i],sentences2[j])
          s4 = datetime.now()
          print("{} \t\t {} \t\t Score: {:.4f}".format(sentences1[i], sentences2[j], score))
          print("{} \t\t {} \t\t Score: {:.4f}".format(sentences1[i], sentences2[j], score2))
          print('time:{}-{}-{}-{}'.format(s1-s0,s2-s1,s3-s2,s4-s3))

if __name__ == '__main__':
    test()