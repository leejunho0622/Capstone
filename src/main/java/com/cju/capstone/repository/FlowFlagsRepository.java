package com.cju.capstone.repository;

import com.cju.capstone.domain.FlowFlags;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface FlowFlagsRepository extends JpaRepository<FlowFlags, Long> {

    /** 페이지에 보이는 플로우들의 플래그를 IN 으로 한 번에 조회 (N+1 방지) */
    List<FlowFlags> findAllByFlowIdIn(Collection<Long> flowIds);
}
