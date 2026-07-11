package com.gateway.controller;

import com.gateway.service.ChainService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/")
@CrossOrigin(origins = "*")
public class UiController {

    @Autowired
    private ChainService chainService;

    @GetMapping
    public String index(Model model) {
        model.addAttribute("chains", chainService.getAllChains());
        model.addAttribute("categories", chainService.getAvailableCategories());
        model.addAttribute("environments", chainService.getGeneratedEnvironments());
        return "index";
    }

    @GetMapping("/chain/{chainName}")
    public String getChainPage(@PathVariable String chainName, Model model) {
        model.addAttribute("chainName", chainName);
        model.addAttribute("chainInfo", chainService.getChainInfo(chainName));
        model.addAttribute("dependencies", chainService.getDependencies(chainName));
        model.addAttribute("pomContent", chainService.getPomContent(chainName));
        model.addAttribute("isAnalyzed", chainService.isChainAnalyzed(chainName));
        model.addAttribute("isEnvironmentGenerated", chainService.isEnvironmentGenerated(chainName));
        return "chain-detail";
    }

    @GetMapping("/visualization")
    public String getVisualizationPage(Model model) {
        model.addAttribute("chains", chainService.getAllChains());
        model.addAttribute("chainsByCategory", chainService.getChainsByCategory());
        model.addAttribute("dependenciesMap", chainService.getAllDependencies());
        return "visualization";
    }

    @GetMapping("/environments")
    public String getEnvironmentsPage(Model model) {
        model.addAttribute("environments", chainService.getGeneratedEnvironments());
        model.addAttribute("totalEnvironments", chainService.getGeneratedEnvironments().size());
        return "environments";
    }

    @GetMapping("/environment/{envName}")
    public String getEnvironmentDetailPage(@PathVariable String envName, Model model) {
        model.addAttribute("envInfo", chainService.getEnvironmentInfo(envName));
        model.addAttribute("envName", envName);
        return "environment-detail";
    }

    @GetMapping("/mcp-status")
    public String getMcpStatusPage(Model model) {
        model.addAttribute("chains", chainService.getAllChains().size());
        model.addAttribute("environments", chainService.getGeneratedEnvironments().size());
        model.addAttribute("categories", chainService.getAvailableCategories());
        model.addAttribute("chainsByCategory", chainService.getChainsByCategory());
        return "mcp-status";
    }
}
