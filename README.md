# Not Yet Another Digital ID: Privacy-preserving Humanitarian Aid Distribution

This repository includes the code in the evaluation section of the paper *"Not Yet Another Digital ID: Privacy-preserving Humanitarian Aid Distribution"* in IEEE S&P 2023. 


> **Abstract** 
> Humanitarian aid-distribution programs help bring physical goods to people in need. 
> Traditional paper-based solutions to support aid distribution do not scale to large populations and are hard to secure. 
> Existing digital solutions solve these issues, at the cost of collecting large amount of personal information. 
> This lack of privacy can endanger recipients' safety and harm their dignity. 
> In collaboration with the International Committee of the Red Cross, we build a safe digital aid-distribution system. 
> We first systematize the requirements such a system should satisfy. 
> We then propose a decentralized solution based on the use of tokens that fulfils the needs of humanitarian organizations. 
> It provides scalability and strong accountability, and, by design, guarantees the recipients' privacy. 
> We provide two instantiations of our design, on a smart card and on a smartphone. 
> We formally prove the security and privacy properties of these solutions, and empirically show that they can operate at scale.

## Purpose of This Repository

This repository aims to provide clear instructions on: 

1. How to implement prototypes of the two solutions we proposed in the paper, i.e., the smart-card-based solution and the smartphone-based solution, 

2. How to reproduce the measurements on the prototypes as written in the evaluation section of the paper

## Structure of This Repository

- `smartcard/` contains the instructions on implementing and evaluating the smart-card prototype

- `smartphone/` contains the instructions on implementing and evaluating the smartphone prototype


## How to Cite

```
@inproceedings{WangLSGT23,
  author    = {Boya Wang and
               Wouter Lueks and
               Justinas Sukaitis and
               Vincent Graf Narbel and
               Carmela Troncoso},
  title     = {{Not Yet Another Digital ID: Privacy-preserving Humanitarian Aid Distribution}},
  year      = {2023},
  booktitle = {{IEEE S&P}},
  note      = {To appear},
}
```

## Contributors

The smart-card prototype was implemented by Laurent Girod and Lorenzo Rovati. 
The smartphone prototype was implemented by Laurent Girod and Nathan Duchenese. 


