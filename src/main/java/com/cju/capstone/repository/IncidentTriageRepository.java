package com.cju.capstone.repository;

import com.cju.capstone.domain.IncidentTriage;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface IncidentTriageRepository extends JpaRepository<IncidentTriage, Long> {

    List<IncidentTriage> findAllByAttackIdIn(Collection<Long> attackIds);
}
