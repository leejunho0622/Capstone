package com.cju.capstone.repository;

import com.cju.capstone.domain.FlowFlags;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FlowFlagsRepository extends JpaRepository<FlowFlags, Long> {

    // 🔥 이게 여기 있어야 맞다
    List<FlowFlags> findAllByFlowIdIn(List<Long> flowIds);
}