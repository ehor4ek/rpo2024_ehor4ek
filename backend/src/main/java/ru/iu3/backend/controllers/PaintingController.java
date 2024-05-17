package ru.iu3.backend.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import ru.iu3.backend.models.Artist;
import ru.iu3.backend.models.Museum;
import ru.iu3.backend.models.Painting;
import ru.iu3.backend.repositories.ArtistRepository;
import ru.iu3.backend.repositories.MuseumRepository;
import ru.iu3.backend.repositories.PaintingRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api/v1")
public class PaintingController {
    @Autowired
    PaintingRepository paintingRepository;

    @Autowired
    MuseumRepository museumRepository;

    @Autowired
    ArtistRepository artistRepository;

    @GetMapping("/paintings")
    public List
    getAllCountries() {
        return paintingRepository.findAll();
    }

    @PostMapping("/paintings")
    public ResponseEntity<Object> createPainting(@RequestBody Painting painting)
            throws Exception {
        try {
            /*if (painting.name.isEmpty() || painting.name.length() == org.springframework.util.StringUtils.countOccurrencesOf(painting.name, " "))
            {
                Map<String, String> map =  new HashMap<>();
                map.put("error", "Painting is empty");
                return ResponseEntity.ok(map);
            }*/

            Optional<Museum>
                    mc = museumRepository.findById(painting.museumid.id);

            if (mc.isPresent()) {
                painting.museumid = mc.get();
            }

            Optional<Artist>
                    ac = artistRepository.findById(painting.artistid.id);

            if (ac.isPresent()) {
                painting.artistid = ac.get();
            }

            Painting nc = paintingRepository.save(painting);
            return new ResponseEntity<Object>(nc, HttpStatus.OK);
        }
        catch(Exception ex) {
            String error;
            if (ex.getMessage().contains("paintings.name_UNIQUE"))
                error = "countyalreadyexists";
            else
                error = "undefinederror";
            Map<String, String>
                    map =  new HashMap<>();
            map.put("error", error);
            return ResponseEntity.ok(map);
        }
    }

    @PutMapping("/paintings/{id}")
    public ResponseEntity<Painting> updatePainting(@PathVariable(value = "id") Long paintingId,
                                           @RequestBody Painting paintingDetails) {
        Painting painting = null;
        Optional
                uu = paintingRepository.findById(paintingId);
        if (uu.isPresent()) {
            painting = (Painting) uu.get();
            if (!paintingDetails.name.isEmpty()) painting.name = paintingDetails.name;
            if (paintingDetails.year != 0) painting.year = paintingDetails.year;
            
            paintingRepository.save(painting);
            return ResponseEntity.ok(painting);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "painting not found");
        }
    }

    @DeleteMapping("/paintings/{id}")
    public ResponseEntity<Object> deletePainting(@PathVariable(value = "id") Long paintingId) {
        Optional<Painting>
                painting = paintingRepository.findById(paintingId);
        Map<String, Boolean>
                resp = new HashMap<>();
        if (painting.isPresent()) {
            paintingRepository.delete(painting.get());
            resp.put("deleted", Boolean.TRUE);
        }
        else
            resp.put("deleted", Boolean.FALSE);
        return ResponseEntity.ok(resp);
    }
}