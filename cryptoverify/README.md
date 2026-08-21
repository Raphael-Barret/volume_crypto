# cryptoverify

Verifier qu'un deploiement respecte la chaine, **sans lire son code source**.

```bash
uv run server.py --storage data/server_storage      # terminal 1
uv run verify.py --storage data/server_storage      # terminal 2
```

```
uv run verify.py --url http://autre-machine:8000    # a distance
uv run verify.py --json evidence/adversary.json     # artefact citable
```

Code de sortie : `0` propre, `1` defauts trouves.

## Pourquoi cet outil existe

Une revendication de securite qu'on ne peut que **croire** n'a pas la meme
valeur qu'une revendication qu'on peut **rejouer**. La batterie est donc
executable par quelqu'un qui n'a acces qu'a une URL, et elle sert deux
publics :

- nous, pour regenerer les chiffres qu'un article cite ;
- **un site**, pour verifier un deploiement qu'il n'a pas construit.

## Les neuf controles

Chaque nom est la question posee, parce que ce nom se retrouve dans
`evidence/adversary.json` puis dans le texte. Un controle nomme
`test_security` ne serait citable par personne.

| Famille | Controle | Question |
|---|---|---|
| canari | `stored_bytes_are_unreadable` | ce que le serveur detient avant la cle est-il illisible ? |
| mesure | `announced_measurement_matches_the_published_manifest` | le manifeste est-il reconstituable, et couvre-t-il la frontiere et le runner ? |
| refus | `key_is_withheld_when_measurement_differs` | un code inattendu obtient-il la cle ? |
| refus | `evidence_is_bound_to_the_nonce` | une ancienne attestation se rejoue-t-elle ? |
| refus | `wrapped_key_never_contains_the_key` | la cle circule-t-elle en clair ? |
| refus | `key_is_bound_to_its_job` | une cle sert-elle sur un autre job ? |
| ordre | `a_key_cannot_be_replayed_on_the_same_job` | une cle rejouee relance-t-elle un traitement ? |
| ordre | `result_does_not_exist_before_the_key` | un resultat existe-t-il avant la remise de la cle ? |
| residence | `plaintext_residency_is_bounded_and_reported` | combien de temps le clair existe-t-il, et le serveur le declare-t-il ? |

## Trois regles tenues partout

1. **Un refus se verifie par l'etat, pas par l'exception.** Une erreur levee
   apres que la cle est partie n'est pas une defense. Chaque controle de refus
   verifie donc aussi que la cle n'a pas bouge et qu'aucun artefact n'a ete
   produit ; c'est ce que rapporte le champ `did_not_move`.
2. **Un controle qui ne peut pas s'executer rend `skip` avec sa raison**, jamais
   `passed`. Sans `--storage`, les controles qui inspectent le disque du
   serveur le disent au lieu de conclure sans preuve.
3. **Rien ne passe par autre chose que HTTP.** La batterie ne connait pas le
   code du serveur, c'est sa raison d'etre.

## La batterie est elle-meme testee

`tests/conformance/test_verifier_catches_defects.py` seme cinq defauts et
verifie que chacun est vu : copie lisible laissee dans le stockage, frontiere
retiree du manifeste, runner retire du manifeste, mesure annoncee divergente
du manifeste, residence non declaree. S'y ajoutent un temoin (un serveur sain
doit passer) et deux tests que `skip` n'est jamais `passed`.

Une batterie qui rend toujours << propre >> est pire qu'aucune batterie : elle
rassure. On n'affirme donc pas qu'un controle protege, on injecte le defaut et
on regarde le controle tomber.

## Limites

Ce que cette batterie **ne** peut **pas** etablir, et qu'il faut obtenir
autrement :

- **elle ne verifie pas le materiel.** La racine de confiance de la
  demonstration est logicielle (`cryptoserve/roots.py`) : elle protege contre
  un serveur modifie par erreur, pas contre un administrateur malveillant.
- **elle ne prouve pas l'absence de fuite hors du stockage inspecte.** Un
  serveur qui recopie le clair ailleurs que dans le dossier des jobs, ou qui
  l'envoie sur le reseau, passerait le controle canari.
- **elle n'evalue pas la base de confiance exclue** : systeme, interpreteur,
  paquets tiers, pilote GPU, materiel. Cette liste est publiee par
  `evidence_report.py` plutot que passee sous silence.
