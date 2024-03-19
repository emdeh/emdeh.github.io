---
layout: post
title: An overview of Transformer architecture and self-attention
date: 2024-03-18 19:50:00-0400
description: A high-level explanation on Transformers and the role of self-attention.
tags: transformers transformer-architecture self-attention encoders decoders sequence-to-sequence encoder-decoder auto-regression
categories: Artificial-Intelligence
thumbnail: /assets/img/2024/202403-transformers.webp
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false
---

In Natural Language Processing (NLP), a transformer architecture is a type of deep learning model that has significantly improved the ability to understand and generate human language. Vaswani et al. introduced transformers in the paper "Attention is All You Need" in 2017 and distinguished them by their application of self-attention mechanisms. Self-attention mechanisms enable a model to weigh the importance of different words within a sentence, regardless of their positional distance from each other.

***Key Features of Transformers***

- **Self-Attention:** allows the model to dynamically focus on different parts of an input as it processes information, enabling it to effectively capture context and relationships between words.
- **Parallel Processing:** Transformers can process entire sequences of data in parallel, which significantly speeds up training and improves the model's ability to handle long sequences. Previous sequence models like RNNs (Recurrent Neural Networks) and LSTMs (Long-Short-Term Memory Networks) could only process data sequentially.
- **Layered Structure:** Transformers comprise multiple layers of self-attention and feed-forward neural networks. A layered structure enables Transformers to learn complex patterns and relationships in the data, which is critical to the depth of their performance on a broad range of NLP tasks.
- **Scalability:** Due to parallel processing and efficient training on large datasets, transformers are highly scalable, making them suitable for cases requiring an understanding of complex and nuanced language.

***Applications***

Many state-of-the-art NLP models, such as BERT (Bidirectional Encoder Representations from Transformers) and GPT (Generative Pretrained Transformer), have a Transformer foundation. These models have set new benchmarks in various NLP tasks, such as text classification, machine translation, question answering, and text generation.

The transformer model's ability to understand context and nuance in text has enabled the development of more sophisticated and interactive AI applications, and it is a cornerstone of modern NLP research.

# The architecture
<br>
Transformer architectures have three broad models:
- Encoders
- Decoders, and
Encoder-Decoders (Sequence-to-Sequence)

## Encoders
Encoders in transformers process input text into a format (vector representations) that captures the essence of the original information.

> ***Encoder models are bidirectional.***

Because encoders consider the context from both before and after a given word within the same layer, they are said to be **bi-directional**. Bi-directional capability contrasts with traditional models that process input in a strict uni-directional sequence (either left-to-right or right-to-left). Thus, it could only incorporate context from one direction at a time in their initial layers.

Imagine the sentence, *`The cat sat on the mat.`* Bidirectionality means that when processing the word *`sat`*, the encoder considers the context of *`The cat`* (words before *`sat`*) and *`on the mat`* (words after *`sat`*) simultaneously. This allows the encoder to understand that *`sat`* is an action performed by *`the cat`* and it occurred *`on the mat`*, integrating full-sentence context into its representation of *`sat`*.

In contrast, **unidirectional** models, such as decoders (see below), would only consider "*`The cat`* when first encountering *`sat`*, meaning it misses the contextual clues provided by *`on the mat`* until later layers, or not at all, depending on the model's overall architecture. 

Bi-directional processing enables transformers to capture a more nuanced and complete understanding of language, which makes them particularly effective for tasks that require a deep understanding of context, such as sentence classification, sentiment analysis, and named entity recognition. 

> ***Encoders use self-attention layers to understand relative context.***

Encoders in transformer models aim to evaluate and understand each part of the input text relative to the entire text. This is achieved by first converting each word or part of the input into a vector representation using embeddings. For each of these vector representations, the model generates three distinct vectors: *Query `(Q)`*, *Key `(K)`*, and *Value `(V)`*. The `Q`, `K`, and `V` vectors are then utilised to calculate attention scores, determining the weight each word's representation should assign to every other word's representation in the input. This weighting process enables the model to determine how much 'attention' or importance each part of the input should give to other parts, effectively allowing each word to consider the context provided by the entire input. This mechanism, known as **self-attention**, is pivotal for the model's ability to capture and utilise contextual information within the input.

Encoder-only models are often used in tasks that require an understanding of the input, like sentence classification or named entity recognition.

## Decoders

> ***Decoders use a masked self-attention layer.***

Self-attention in decoders is said to be **masked**. Masking prevents a decoder from 'seeing' future parts of the sequence during training, ensuring each word prediction is based only on already generated words. In other words, during the generation of an output sequence, each position can only attend to positions that preceded the current position in the sequence. This constraint is crucial for text generation, where models predict the next word based on the previous ones. 

For example, imagine the decoder is generating the text *`The quick brown fox.`* When it's predicting the word after *`The quick,`* the masked self-attention mechanism allows the decoder to consider *`The`* and *`quick`* but not *`brown`* or *`fox`* because those words are in the future relative to the current position being predicted. This masking effectively enforces a uni-directional flow of information, ensuring that the model generates each word based solely on preceding words, preserving the natural order of text generation. 


> ***Because of masked self-attention, decoders are uni-directional.***

They generate output one element at a time in a forward direction. In decoders, the future context is deliberately obscured to mimic the process of creating language one word at a time, making the decoding process fundamentally uni-directional.

If decoders were not uni-directional and could instead attend to the entire input sequence indiscriminately (similar to encoders), the integrity of the generated output sequence would be compromised. Specifically, the following issues could arise:

- *Loss of Sequential Generation Logic:* Predicting the next word becomes moot if the decoder has access to future words, undermining the process of sequential text generation.
- *Incoherent or Circular Outputs:* Due to premature knowledge of future context, outputs might repeat or loop without a logical progression.
- *Compromised Learning Objective:* The model's focus shifts from generating text based on learned structures to merely matching patterns, diluting the essence of language generation.

> ***The generation of each element of the output sequence one at a time is Auto-Regression.***

Generated each element of the output one at a time, based on the previously generated elements, is known as **Auto-Regression**. The auto-regressive property necessitates the use of masked self-attention in the decoder, as it relies on the premise that each step in the generation process only has access to previous steps.

In summary, decoders are *uni-directional* because their *self-attention* layer is masked. Masking supports the *auto-regressive* nature of the generation process, ensuring that each step in generating the output can only use information from the steps that have already occurred.

Decoder-only models are particularly useful at generative tasks, like text generation.

## Encoders-decoders
Are also known as **sequence-to-sequence**. These models are good for generative tasks that are based on an input, such as translation or summarisation.

# Self-Attention Layers
**Attention layers** refers to any layer within a neural network that applies some form of the *attention mechanism*. Attention mechanisms allow models to focus on different parts of the input data with varying degrees of emphasis.

> ***Self-Attention is one type of attention mechanism.***

Self-Attention in transformer models enables each position in the input sequence to attend to all positions within the same sequence. Self-Attention enables transformers to process and interpret sequences of input data, such as sentences in natural language processing (NLP) and dynamically weigh the relevance of all parts of the input data against every other part when processing any single part, enabling the incorporation of relatively weighted context from the entire sequence.

In other words, self-attention allows a model to understand the relationships between words, regardless of their positional distance. Here's a more detailed look at how self-attention works:

For example, imagine the sentence: *`The cat purrs.`*

**Step 1 - Input representation**\
First, each word in the sentence (*`The`*, *`cat`*, *`purrs`*) is converted into a vector using embeddings. These vectors contain each word's initial context.

**Step 2 - Query, Key, and Value Vectors**\
For each word, three vectors are generated from its embedding: a Query vector (`Q`), a Key vector (`K`), and a Value vector (`V`). This is done through linear transformations, which essentially means multiplying the word's embedding by different weight matrices for `Q`, `K`, and `V`.

**Step 3 - Calculating attention scores**\
The "dot product" of the Query vector for `purrs` is calculated with the Key vector of every word in the sentence, including itself. Calculating the dot product with the Key vector (`K`) of every other word produces scores that represent how much attention `purrs` should pay to each word in the sentence, including `The` and `cat`.

**Step 4 - Softmax to Determine Weights**\
These scores converted into weights that sum to 1 through a mathematical normalisation process (a softmax function). The weights quantify the relevance of each word's information to the word `purrs`.

**Step 5 - Weighted Sum and Output**\
The weights are used to create a weighted sum of the Value vectors, which incorporates information from the entire sentence into the representation of `purrs`. For instance, the high weight of `cat` (since it's directly related to `purrs`) ensures that `purrs` is understood in the context of *`The cat`*, reinforcing that it's the cat doing the purring.

> ***The result is contextual representation.***

Thanks to the self-attention mechanism, the output vector for "purrs" now contains information about the word itself and how it relates to the other words in the sentence.

This process is repeated for every word, enabling the encoder to understand and represent each word in the context of the entire sentence. Through this mechanism, transformers achieve a deep understanding of the text, considering the meaning of individual words and their broader context within the sentence.

So clever.

#### Sources
- Self-Attention is all you need
- Wikipedia
- Huggingface.co NLP Course