package ru.iu3.backend.controllers;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.iu3.backend.models.Artist;
import ru.iu3.backend.models.Country;
import ru.iu3.backend.repositories.CountryRepository;
import ru.iu3.backend.tools.DataValidationException;

import javax.persistence.OneToMany;
import javax.validation.Valid;
import java.util.*;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api/v1")
public class CountryController {
    @Autowired
    CountryRepository countryRepository;

    @JsonIgnore
    @OneToMany(mappedBy = "country")
    public List<Artist> artists = new ArrayList<Artist>();

    @GetMapping("/countries")
    public List
    getAllCountries() {
        return countryRepository.findAll();
    }

    @GetMapping("/countries/{id}/artists")
    public ResponseEntity<List<Artist>> getCountryArtists(@PathVariable(value = "id") Long countryId) {
        Optional<Country> cc = countryRepository.findById(countryId);
        if (cc.isPresent()) {
            return ResponseEntity.ok(cc.get().artists);
        }
        return ResponseEntity.ok(new ArrayList<Artist>());
    }

    @GetMapping("/countries/{id}")
    public ResponseEntity<Country> getCountry(@PathVariable(value = "id") Long countryId)
            throws DataValidationException {
        Country country = countryRepository.findById(countryId)
                .orElseThrow(()->new DataValidationException("Страна с таким индексом не найдена"));
        return ResponseEntity.ok(country);
    }


    @PostMapping("/countries")
    public ResponseEntity<Object>
    createCountry(@Valid @RequestBody Country country)
            throws DataValidationException {
        try {
            Country nc = countryRepository.save(country);
            return new ResponseEntity<Object>(nc, HttpStatus.OK);
        }
        catch(Exception ex) {
            String error;
            if (ex.getMessage().contains("countries.name_UNIQUE"))
                throw new DataValidationException("Эта страна уже есть в базе");
            else
                throw new DataValidationException("Неизвестная ошибка");
        }
    }

    @PutMapping("/countries/{id}")
    public ResponseEntity<Country> updateCountry(@PathVariable(value = "id") Long countryId, @Valid @RequestBody Country countryDetails)
            throws DataValidationException {
            try {
                Country country = countryRepository.findById(countryId)
                        .orElseThrow(() -> new DataValidationException("Страна с таким индексом не найдена"));
                country.name = countryDetails.name;
                countryRepository.save(country);
                return ResponseEntity.ok(country);
            }
            catch (Exception ex) {
                String error;
                if (ex.getMessage().contains("countries.name_UNIQUE"))
                    throw new DataValidationException("Эта страна уже есть в базе");
                else
                    throw new DataValidationException("Неизвестная ошибка");
            }
    }

    @PostMapping("/deletecountries")
    public ResponseEntity deleteCountries(@Valid @RequestBody List<Country> countries) {
        countryRepository.deleteAll(countries);
        return new ResponseEntity(HttpStatus.OK);
    }

    @DeleteMapping("/countries/{id}")
    public ResponseEntity<Object> deleteCountry(@PathVariable(value = "id") Long countryId) {
        Optional<Country>
                country = countryRepository.findById(countryId);
        Map<String, Boolean>
                resp = new HashMap<>();
        if (country.isPresent()) {
            countryRepository.delete(country.get());
            resp.put("deleted", Boolean.TRUE);
        }
        else
            resp.put("deleted", Boolean.FALSE);
        return ResponseEntity.ok(resp);
    }
}